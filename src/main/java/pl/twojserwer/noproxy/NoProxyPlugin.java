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

    // Cache dla bypass IP
    private Set<String> cachedBypassIps = ConcurrentHashMap.newKeySet();

    // Cache dla zweryfikowanych IP (IP -> Timestamp)
    private final Map<String, Long> verifiedCache = new ConcurrentHashMap<>();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        getServer().getPluginManager().registerEvents(this, this);

        if (getConfig().getBoolean("bypass-api.enabled")) {
            int interval = getConfig().getInt("bypass-api.refresh-interval", 60);
            Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::refreshBypassList, 0L, interval * 20L);
        }

        // Zadanie czyszczące cache co godzinę
        Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::cleanupVerifiedCache, 1200L, 72000L);
        
        getLogger().info("NoProxyGuard zaladowany! Cache aktywny.");
    }

    private void cleanupVerifiedCache() {
        long now = System.currentTimeMillis();
        int removed = 0;
        Iterator<Map.Entry<String, Long>> it = verifiedCache.entrySet().iterator();
        while (it.hasNext()) {
            if (now > it.next().getValue()) {
                it.remove();
                removed++;
            }
        }
        if (removed > 0) {
            getLogger().info("Wyczyszczono " + removed + " wygaslych wpisow z cache IP.");
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
                    this.cachedBypassIps = ConcurrentHashMap.newKeySet();
                    this.cachedBypassIps.addAll(newSet);
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

        List<String> whiteNicks = getConfig().getStringList("whitelist.nicks");
        for (String whiteNick : whiteNicks) {
            if (whiteNick.equalsIgnoreCase(nick)) return;
        }

        if (getConfig().getStringList("whitelist.ips").contains(ip)) return;
        if (cachedBypassIps.contains(ip)) return;

        // Cache sprawdzania
        if (getConfig().getBoolean("cache.enabled", true)) {
            Long expirationTime = verifiedCache.get(ip);
            if (expirationTime != null && System.currentTimeMillis() < expirationTime) {
                return;
            }
        }

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
                } else {
                    // Dodaj do cache
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
