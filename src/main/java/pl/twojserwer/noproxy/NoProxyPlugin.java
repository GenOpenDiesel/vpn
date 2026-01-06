package pl.twojserwer.noproxy;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
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
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;

public class NoProxyPlugin extends JavaPlugin implements Listener {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Gson gson = new Gson();
    
    // Cache dla bypass IP (używamy Set dla szybkiego sprawdzania O(1))
    private Set<String> cachedBypassIps = ConcurrentHashMap.newKeySet();
    
    @Override
    public void onEnable() {
        saveDefaultConfig();
        getServer().getPluginManager().registerEvents(this, this);

        // Uruchomienie zadania odświeżania listy bypass
        if (getConfig().getBoolean("bypass-api.enabled")) {
            int interval = getConfig().getInt("bypass-api.refresh-interval", 60);
            Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::refreshBypassList, 0L, interval * 20L);
        }
        
        getLogger().info("NoProxyGuard zaladowany!");
    }

    /**
     * Pobiera listę IP z lokalnego API i zapisuje w pamięci podręcznej.
     */
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
                    
                    // Podmieniamy cache
                    this.cachedBypassIps = ConcurrentHashMap.newKeySet();
                    this.cachedBypassIps.addAll(newSet);
                }
            } else {
                getLogger().warning("Blad pobierania bypass IP. Kod: " + response.statusCode());
            }
        } catch (Exception e) {
            getLogger().warning("Wyjatek podczas pobierania bypass IP: " + e.getMessage());
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        String ip = event.getAddress().getHostAddress();
        String nick = event.getName();

        // 1. Sprawdzenie Whitelisty z Configu (Nick)
        List<String> whiteNicks = getConfig().getStringList("whitelist.nicks");
        for (String whiteNick : whiteNicks) {
            if (whiteNick.equalsIgnoreCase(nick)) return; // Wpuszczamy
        }

        // 2. Sprawdzenie Whitelisty z Configu (IP)
        if (getConfig().getStringList("whitelist.ips").contains(ip)) return;

        // 3. Sprawdzenie Cache z lokalnego API (Bardzo szybkie)
        if (cachedBypassIps.contains(ip)) {
            // Opcjonalnie: logowanie debugowe
            // getLogger().info("Gracz " + nick + " pominal weryfikacje (Active IP API).");
            return;
        }

        // 4. Sprawdzenie w Okaeri (tylko jeśli nie jest na whiteliscie)
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
                    .timeout(Duration.ofSeconds(3)) // Krótki timeout żeby nie blokować gracza
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                JsonObject suggestions = json.getAsJsonObject("suggestions");

                // Sprawdzamy sugestię 'block'
                boolean shouldBlock = suggestions.has("block") && suggestions.get("block").getAsBoolean();

                // Alternatywnie można sprawdzać 'verify', jeśli wolisz
                // boolean verify = suggestions.get("verify").getAsBoolean();

                if (shouldBlock) {
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, 
                            color(getConfig().getString("messages.kick")));
                    getLogger().info("Zablokowano polaczenie VPN: " + event.getName() + " (" + ip + ")");
                }
            } else {
                getLogger().warning("Okaeri API zwrocilo blad: " + response.statusCode());
                handleFailOpen(event);
            }

        } catch (Exception e) {
            getLogger().log(Level.SEVERE, "Blad polaczenia z Okaeri API", e);
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
