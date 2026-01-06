package pl.twojserwer.noproxy;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

public class NoProxyPlugin extends JavaPlugin implements Listener {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Gson gson = new Gson();

    // Cache dla bypass IP (whitelist z API)
    private volatile Set<String> cachedBypassIps = ConcurrentHashMap.newKeySet();

    // Cache dla zweryfikowanych IP (IP -> Timestamp) - Dobre IP
    private final Map<String, Long> verifiedCache = new ConcurrentHashMap<>();

    // Cache dla zablokowanych IP (IP -> Timestamp) - Złe IP (NOWOŚĆ dla wydajności)
    private final Map<String, Long> blockedCache = new ConcurrentHashMap<>();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        
        // 1. Najpierw pobierz whitelistę (synchronicznie), aby nie blokować graczy na starcie
        if (getConfig().getBoolean("bypass-api.enabled")) {
            getLogger().info("Pobieranie whitelisty z API (start)...");
            refreshBypassList(); // Wywołanie bezpośrednie (blokujące)
        }

        // Rejestracja zdarzeń dopiero po pobraniu whitelisty
        getServer().getPluginManager().registerEvents(this, this);

        // Uruchomienie cyklicznego odświeżania (asynchronicznie)
        if (getConfig().getBoolean("bypass-api.enabled")) {
            int interval = getConfig().getInt("bypass-api.refresh-interval", 60);
            // Pierwsze uruchomienie po upływie interwału, bo raz już pobraliśmy na starcie
            Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::refreshBypassList, interval * 20L, interval * 20L);
        }

        // Zadanie czyszczące oba cache co godzinę
        Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::cleanupCaches, 1200L, 72000L);
        
        getLogger().info("NoProxyGuard zaladowany! Cache i whitelista aktywne.");
    }

    private void cleanupCaches() {
        long now = System.currentTimeMillis();
        
        // Czyszczenie verifiedCache (dobre IP)
        int removedVerified = 0;
        Iterator<Map.Entry<String, Long>> itVerified = verifiedCache.entrySet().iterator();
        while (itVerified.hasNext()) {
            if (now > itVerified.next().getValue()) {
                itVerified.remove();
                removedVerified++;
            }
        }

        // Czyszczenie blockedCache (złe IP)
        int removedBlocked = 0;
        Iterator<Map.Entry<String, Long>> itBlocked = blockedCache.entrySet().iterator();
        while (itBlocked.hasNext()) {
            if (now > itBlocked.next().getValue()) {
                itBlocked.remove();
                removedBlocked++;
            }
        }

        if (removedVerified > 0 || removedBlocked > 0) {
            getLogger().info("Wyczyszczono cache: " + removedVerified + " dobrych, " + removedBlocked + " zablokowanych.");
        }
    }

    private void refreshBypassList() {
        String url = getConfig().getString("bypass-api.url");
        String apiKey = getConfig().getString("bypass-api.x-api-key");

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("x-api-key", apiKey)
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                if (json.has("success") && json.get("success").getAsBoolean()) {
                    JsonArray ips = json.getAsJsonArray("ips");
                    Set<String> newSet = new HashSet<>();
                    ips.forEach(element -> newSet.add(element.getAsString()));
                    
                    // 2. Jeśli IP jest na nowej whieliście, usuń je z blockedCache
                    for (String ip : newSet) {
                        if (blockedCache.containsKey(ip)) {
                            blockedCache.remove(ip);
                            // Opcjonalnie log:
                            // getLogger().info("Odblokowano IP z cache dzieki whiteliscie: " + ip);
                        }
                    }

                    // Bezpieczna podmiana seta (thread-safe)
                    Set<String> concurrentSet = ConcurrentHashMap.newKeySet();
                    concurrentSet.addAll(newSet);
                    this.cachedBypassIps = concurrentSet;
                }
            }
        } catch (Exception e) {
            getLogger().warning("Blad pobierania bypass IP: " + e.getMessage());
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        String ip = event.getAddress().getHostAddress();
        String nick = event.getName();

        // 1. Whitelista Nicków
        List<String> whiteNicks = getConfig().getStringList("whitelist.nicks");
        for (String whiteNick : whiteNicks) {
            if (whiteNick.equalsIgnoreCase(nick)) return;
        }

        // 2. Whitelista IP (lokalna i z API)
        if (getConfig().getStringList("whitelist.ips").contains(ip)) return;
        if (cachedBypassIps.contains(ip)) return;

        // 3. Sprawdzenie Cache ZABLOKOWANYCH (Szybki odrzut dla wydajności)
        Long blockedExpiration = blockedCache.get(ip);
        if (blockedExpiration != null && System.currentTimeMillis() < blockedExpiration) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, 
                    color(getConfig().getString("messages.kick")));
            return;
        }

        // 4. Sprawdzenie Cache DOBRYCH (Szybkie wpuszczenie)
        if (getConfig().getBoolean("cache.enabled", true)) {
            Long expirationTime = verifiedCache.get(ip);
            if (expirationTime != null && System.currentTimeMillis() < expirationTime) {
                return;
            }
        }

        // 5. Sprawdzenie w API Okaeri (jeśli nie ma w żadnym cache)
        if (getConfig().getBoolean("okaeri.enabled")) {
            checkOkaeri(event, ip);
        }
    }

    private void checkOkaeri(AsyncPlayerPreLoginEvent event, String ip) {
        String baseUrl = getConfig().getString("okaeri.url");
        if (!baseUrl.endsWith("/")) baseUrl += "/";
        String fullUrl = baseUrl + ip;
        String token = getConfig().getString("okaeri.api-key");

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(fullUrl))
                    .header("Authorization", "Bearer " + token)
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                JsonObject suggestions = json.getAsJsonObject("suggestions");
                boolean shouldBlock = suggestions.has("block") && suggestions.get("block").getAsBoolean();

                if (shouldBlock) {
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, 
                            color(getConfig().getString("messages.kick")));
                    getLogger().info("Zablokowano VPN: " + event.getName() + " (" + ip + ")");
                    
                    // Dodaj do blockedCache (np. na czas taki sam jak pozytywny cache lub sztywno np. 15 min)
                    if (getConfig().getBoolean("cache.enabled", true)) {
                        long hours = getConfig().getInt("cache.duration-hours", 12);
                        // Dla zablokowanych też używamy tego czasu, bo jeśli trafią na whitelistę, to i tak ich zdejmiemy
                        long expiration = System.currentTimeMillis() + (hours * 60 * 60 * 1000L);
                        blockedCache.put(ip, expiration);
                    }
                } else {
                    // Dodaj do verifiedCache
                    if (getConfig().getBoolean("cache.enabled", true)) {
                        long hours = getConfig().getInt("cache.duration-hours", 12);
                        long expiration = System.currentTimeMillis() + (hours * 60 * 60 * 1000L);
                        verifiedCache.put(ip, expiration);
                    }
                }
            } else {
                handleFailOpen(event);
            }
        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "Blad Okaeri", e);
            handleFailOpen(event);
        }
    }

    private void handleFailOpen(AsyncPlayerPreLoginEvent event) {
        if (!getConfig().getBoolean("okaeri.fail-open")) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, 
                    color(getConfig().getString("messages.error")));
        }
    }

    private String color(String msg) {
        return ChatColor.translateAlternateColorCodes('&', msg);
    }
}
