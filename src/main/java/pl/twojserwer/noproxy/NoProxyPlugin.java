package pl.twojserwer.noproxy;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
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

public class NoProxyPlugin extends JavaPlugin implements Listener, CommandExecutor {

    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Gson gson = new Gson();

    // Cache dla bypass IP (whitelist z API)
    private volatile Set<String> cachedBypassIps = ConcurrentHashMap.newKeySet();

    // Cache dla zweryfikowanych IP (IP -> Timestamp) - Dobre IP
    private final Map<String, Long> verifiedCache = new ConcurrentHashMap<>();

    // Cache dla zablokowanych IP (IP -> Timestamp) - Złe IP
    private final Map<String, Long> blockedCache = new ConcurrentHashMap<>();

    // Plik i konfiguracja banów
    private File bansFile;
    private FileConfiguration bansConfig;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        
        // Inicjalizacja pliku bans.yml
        createBansConfig();

        // Rejestracja komendy
        getCommand("vpn").setExecutor(this);

        // 1. Najpierw pobierz whitelistę (synchronicznie), aby nie blokować graczy na starcie
        if (getConfig().getBoolean("bypass-api.enabled")) {
            getLogger().info("Pobieranie whitelisty z API (start)...");
            refreshBypassList(); // Wywołanie bezpośrednie (blokujące)
        }

        // Rejestracja zdarzeń
        getServer().getPluginManager().registerEvents(this, this);

        // Uruchomienie cyklicznego odświeżania (asynchronicznie)
        if (getConfig().getBoolean("bypass-api.enabled")) {
            int interval = getConfig().getInt("bypass-api.refresh-interval", 60);
            Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::refreshBypassList, interval * 20L, interval * 20L);
        }

        // Zadanie czyszczące cache
        Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::cleanupCaches, 1200L, 72000L);
        
        getLogger().info("NoProxyGuard zaladowany! System banowania aktywny.");
    }

    // --- Obsługa bans.yml ---
    private void createBansConfig() {
        bansFile = new File(getDataFolder(), "bans.yml");
        if (!bansFile.exists()) {
            try {
                bansFile.createNewFile();
            } catch (IOException e) {
                getLogger().severe("Nie udalo sie utworzyc bans.yml!");
            }
        }
        bansConfig = YamlConfiguration.loadConfiguration(bansFile);
    }

    private void saveBansConfig() {
        try {
            bansConfig.save(bansFile);
        } catch (IOException e) {
            getLogger().severe("Nie udalo sie zapisac bans.yml!");
        }
    }

    // --- Obsługa Komend ---
    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("noproxy.admin")) {
            sender.sendMessage(color("&cBrak uprawnien."));
            return true;
        }

        if (args.length == 0) {
            sender.sendMessage(color("&cUzycie:"));
            sender.sendMessage(color("&c/vpn ban <nick> <powod> &7- Blokuje IP gracza dla innych"));
            sender.sendMessage(color("&c/vpn unban <nick> &7- Zdejmuje blokade IP przypisana do gracza"));
            return true;
        }

        // /vpn ban <nick> <powod>
        if (args[0].equalsIgnoreCase("ban")) {
            if (args.length < 3) {
                sender.sendMessage(color("&cPodaj nick i powod! Przyklad: /vpn ban Player1 Alt-Konto"));
                return true;
            }

            String targetName = args[1];
            
            // Budowanie powodu ze spacji
            StringBuilder reasonBuilder = new StringBuilder();
            for (int i = 2; i < args.length; i++) reasonBuilder.append(args[i]).append(" ");
            String reason = reasonBuilder.toString().trim();

            Player target = Bukkit.getPlayer(targetName);
            if (target == null) {
                sender.sendMessage(color("&cGracz " + targetName + " musi byc online, aby pobrac jego IP!"));
                return true;
            }

            String ip = target.getAddress().getAddress().getHostAddress();
            String ipKey = ip.replace(".", "_");

            // Zapis do bans.yml
            bansConfig.set("bans." + ipKey + ".user", targetName);
            bansConfig.set("bans." + ipKey + ".reason", reason);
            saveBansConfig();

            sender.sendMessage(color("&aZablokowano IP &e" + ip + " &adla wszystkich OPROCZ gracza &e" + targetName));
            return true;
        }

        // /vpn unban <nick>
        if (args[0].equalsIgnoreCase("unban")) {
            if (args.length < 2) {
                sender.sendMessage(color("&cPodaj nick gracza, ktorego IP chcesz odblokowac!"));
                return true;
            }
            String targetName = args[1];
            boolean found = false;

            if (bansConfig.getConfigurationSection("bans") != null) {
                for (String key : bansConfig.getConfigurationSection("bans").getKeys(false)) {
                    String assignedUser = bansConfig.getString("bans." + key + ".user");
                    if (assignedUser != null && assignedUser.equalsIgnoreCase(targetName)) {
                        bansConfig.set("bans." + key, null); // Usunięcie sekcji
                        found = true;
                    }
                }
            }

            if (found) {
                saveBansConfig();
                sender.sendMessage(color("&aZdjeto blokady IP przypisane do gracza &e" + targetName));
            } else {
                sender.sendMessage(color("&cNie znaleziono blokad IP przypisanych do nicku &e" + targetName));
            }
            return true;
        }

        return true;
    }

    private void cleanupCaches() {
        long now = System.currentTimeMillis();
        
        // Czyszczenie verifiedCache
        verifiedCache.entrySet().removeIf(entry -> now > entry.getValue());

        // Czyszczenie blockedCache
        blockedCache.entrySet().removeIf(entry -> now > entry.getValue());
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
                    
                    for (String ip : newSet) {
                        blockedCache.remove(ip);
                    }

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

        // 0. SPRAWDZENIE BANÓW NA IP (System "Tylko dla jednego gracza")
        // Sprawdzamy, czy to IP jest w bazie banów
        String ipKey = ip.replace(".", "_");
        if (bansConfig.contains("bans." + ipKey)) {
            String allowedUser = bansConfig.getString("bans." + ipKey + ".user");
            
            // Jeśli nick gracza wchodzącego NIE jest tym dozwolonym -> Blokada
            if (!nick.equalsIgnoreCase(allowedUser)) {
                String reason = bansConfig.getString("bans." + ipKey + ".reason", "IP Restricted");
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, 
                        color("&cTo IP jest przypisane wylacznie do gracza: &e" + allowedUser + "\n\n&cPowod: &7" + reason));
                return;
            }
            // Jeśli to ten gracz (allowedUser), to przepuszczamy go dalej
            // (wciąż może go sprawdzić Okaeri/VPN, ale zakładamy, że właściciel IP ma prawo wejść)
        }

        // 1. Whitelista Nicków (config)
        List<String> whiteNicks = getConfig().getStringList("whitelist.nicks");
        for (String whiteNick : whiteNicks) {
            if (whiteNick.equalsIgnoreCase(nick)) return;
        }

        // 2. Whitelista IP (lokalna i z API)
        if (getConfig().getStringList("whitelist.ips").contains(ip)) return;
        if (cachedBypassIps.contains(ip)) return;

        // 3. Sprawdzenie Cache ZABLOKOWANYCH
        Long blockedExpiration = blockedCache.get(ip);
        if (blockedExpiration != null && System.currentTimeMillis() < blockedExpiration) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, 
                    color(getConfig().getString("messages.kick")));
            return;
        }

        // 4. Sprawdzenie Cache DOBRYCH
        if (getConfig().getBoolean("cache.enabled", true)) {
            Long expirationTime = verifiedCache.get(ip);
            if (expirationTime != null && System.currentTimeMillis() < expirationTime) {
                return;
            }
        }

        // 5. Sprawdzenie w API Okaeri
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
                    
                    if (getConfig().getBoolean("cache.enabled", true)) {
                        long hours = getConfig().getInt("cache.duration-hours", 12);
                        long expiration = System.currentTimeMillis() + (hours * 60 * 60 * 1000L);
                        blockedCache.put(ip, expiration);
                    }
                } else {
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
