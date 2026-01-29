package pl.twojserwer.noproxy;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.ConfigurationSection;
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

    // Cache
    private volatile Set<String> cachedBypassIps = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> verifiedCache = new ConcurrentHashMap<>();
    private final Map<String, Long> blockedCache = new ConcurrentHashMap<>();

    // --- SYSTEM BANOWANIA (TRACKING) ---
    private File bansFile;
    private FileConfiguration bansConfig;
    
    // Mapa IP -> Nick (szybkie sprawdzanie czy IP jest zajęte)
    private final Map<String, String> ipLocks = new ConcurrentHashMap<>();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        createBansConfig();
        loadBansIntoMemory(); // Ładowanie blokad do pamięci

        getCommand("vpn").setExecutor(this);

        // Whitelista
        if (getConfig().getBoolean("bypass-api.enabled")) {
            refreshBypassList();
            int interval = getConfig().getInt("bypass-api.refresh-interval", 60);
            Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::refreshBypassList, interval * 20L, interval * 20L);
        }

        getServer().getPluginManager().registerEvents(this, this);
        Bukkit.getScheduler().runTaskTimerAsynchronously(this, this::cleanupCaches, 1200L, 72000L);
        
        getLogger().info("NoProxyGuard v1.2.0 zaladowany! System Tracking IP aktywny.");
    }

    // --- Konfiguracja bans.yml ---
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
            e.printStackTrace();
        }
    }

    // Ładuje aktywne blokady do mapy ipLocks dla szybkiego dostępu
    private void loadBansIntoMemory() {
        ipLocks.clear();
        ConfigurationSection section = bansConfig.getConfigurationSection("tracked");
        if (section == null) return;

        long now = System.currentTimeMillis();
        for (String user : section.getKeys(false)) {
            String ip = section.getString(user + ".ip");
            long expires = section.getLong(user + ".expires", 0);

            // Jeśli blokada jest ważna i ma IP, dodaj do mapy
            if (ip != null && !ip.isEmpty() && now < expires) {
                ipLocks.put(ip, user);
            }
        }
        getLogger().info("Zaladowano " + ipLocks.size() + " aktywnych blokad IP.");
    }

    // --- Komendy /vpn ban & unban ---
    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!sender.hasPermission("noproxy.admin")) {
            sender.sendMessage(color("&cBrak uprawnien."));
            return true;
        }

        if (args.length == 0) {
            sender.sendMessage(color("&cUzycie: /vpn <ban/unban> <nick> [powod]"));
            return true;
        }

        // BAN: Dodaje gracza do śledzonych
        if (args[0].equalsIgnoreCase("ban")) {
            if (args.length < 2) {
                sender.sendMessage(color("&cPodaj nick! /vpn ban <nick> [powod]"));
                return true;
            }
            String targetName = args[1];
            String reason = (args.length > 2) ? String.join(" ", args).substring(args[0].length() + args[1].length() + 2) : "Banned";

            // Sprawdź czy gracz jest online, aby od razu zablokować jego IP
            Player target = Bukkit.getPlayer(targetName);
            String currentIp = (target != null) ? target.getAddress().getAddress().getHostAddress() : null;

            long durationDays = getConfig().getInt("bans.duration-days", 3);
            long expires = System.currentTimeMillis() + (durationDays * 24 * 60 * 60 * 1000L);

            // Zapis do bans.yml
            bansConfig.set("tracked." + targetName + ".reason", reason);
            bansConfig.set("tracked." + targetName + ".expires", expires);
            
            if (currentIp != null) {
                bansConfig.set("tracked." + targetName + ".ip", currentIp);
                ipLocks.put(currentIp, targetName); // Aktualizacja mapy w pamięci
                sender.sendMessage(color("&aRozpoczeto sledzenie gracza &e" + targetName + "&a. Zablokowano IP: &e" + currentIp));
            } else {
                bansConfig.set("tracked." + targetName + ".ip", ""); // Puste IP, zaktualizuje się przy wejściu
                sender.sendMessage(color("&aDodano gracza &e" + targetName + " &ado listy. IP zostanie zablokowane przy jego wejsciu."));
            }
            saveBansConfig();
            return true;
        }

        // UNBAN: Usuwa gracza ze śledzonych i zwalnia IP
        if (args[0].equalsIgnoreCase("unban")) {
            if (args.length < 2) {
                sender.sendMessage(color("&cPodaj nick!"));
                return true;
            }
            String targetName = args[1];

            if (bansConfig.contains("tracked." + targetName)) {
                // Usuń z mapy pamięci
                String savedIp = bansConfig.getString("tracked." + targetName + ".ip");
                if (savedIp != null && ipLocks.containsKey(savedIp) && ipLocks.get(savedIp).equals(targetName)) {
                    ipLocks.remove(savedIp);
                }

                // Usuń z pliku
                bansConfig.set("tracked." + targetName, null);
                saveBansConfig();
                sender.sendMessage(color("&aGracz &e" + targetName + " &anie jest juz sledzony. IP odblokowane."));
            } else {
                sender.sendMessage(color("&cNie znaleziono gracza &e" + targetName + " &aw bazie blokad."));
            }
            return true;
        }
        return true;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        String ip = event.getAddress().getHostAddress();
        String nick = event.getName();
        long now = System.currentTimeMillis();

        // 1. SPRAWDZANIE CZY IP JEST ZAJĘTE PRZEZ INNEGO GRACZA
        // Sprawdzamy w mapie pamięci (szybko)
        if (ipLocks.containsKey(ip)) {
            String owner = ipLocks.get(ip);
            
            // Sprawdź czy rezerwacja nie wygasła
            long expires = bansConfig.getLong("tracked." + owner + ".expires", 0);
            if (now > expires) {
                // Wygasła - usuwamy blokadę
                ipLocks.remove(ip);
                // Nie usuwamy usera z configu całkowicie, tylko pozwalamy IP zwolnić? 
                // Zgodnie z założeniem "pamiętać 3 dni", jeśli minęło, to IP jest wolne.
            } else {
                // Rezerwacja aktywna. Jeśli to nie właściciel -> KICK
                if (!owner.equalsIgnoreCase(nick)) {
                    String msg = getConfig().getString("messages.ip-restricted", "&cIP reserved for {USER}").replace("{USER}", owner);
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_BANNED, color(msg));
                    return;
                }
            }
        }

        // 2. AKTUALIZACJA TRACKINGU (Jeśli to gracz śledzony wchodzi z nowego lub starego IP)
        if (bansConfig.contains("tracked." + nick)) {
            // Przedłużamy czas ważności (3 dni od TERAZ)
            long durationDays = getConfig().getInt("bans.duration-days", 3);
            long newExpires = now + (durationDays * 24 * 60 * 60 * 1000L);
            
            String oldIp = bansConfig.getString("tracked." + nick + ".ip");

            // Jeśli IP się zmieniło
            if (!ip.equals(oldIp)) {
                // Zwolnij stare IP z mapy blokad
                if (oldIp != null && !oldIp.isEmpty() && ipLocks.getOrDefault(oldIp, "").equals(nick)) {
                    ipLocks.remove(oldIp);
                }
                // Zablokuj nowe IP
                ipLocks.put(ip, nick);
                getLogger().info("Zaktualizowano IP dla sledzonego gracza " + nick + ": " + oldIp + " -> " + ip);
            } else {
                // To samo IP - upewnij się, że jest w mapie (np. po przeładowaniu)
                ipLocks.put(ip, nick);
            }

            // Zapisz zmiany w configu
            bansConfig.set("tracked." + nick + ".ip", ip);
            bansConfig.set("tracked." + nick + ".expires", newExpires);
            saveBansConfig();
        }

        // DALSZA WERYFIKACJA (Whitelisty, VPN, Okaeri)
        // Jeśli gracz przeszedł weryfikację "Bans", sprawdzamy go normalnie pod kątem VPN
        
        // Whitelista Nicków
        List<String> whiteNicks = getConfig().getStringList("whitelist.nicks");
        for (String whiteNick : whiteNicks) {
            if (whiteNick.equalsIgnoreCase(nick)) return;
        }

        // Whitelista IP
        if (getConfig().getStringList("whitelist.ips").contains(ip)) return;
        if (cachedBypassIps.contains(ip)) return;

        // Cache Zablokowanych
        Long blockedExpiration = blockedCache.get(ip);
        if (blockedExpiration != null && now < blockedExpiration) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, color(getConfig().getString("messages.kick")));
            return;
        }

        // Okaeri API
        if (getConfig().getBoolean("okaeri.enabled")) {
            // Pomijamy sprawdzanie Okaeri dla graczy z verifiedCache
            Long verifiedExp = verifiedCache.get(ip);
            if (verifiedExp == null || now > verifiedExp) {
                checkOkaeri(event, ip);
            }
        }
    }

    // --- Reszta metod bez zmian istotnych ---
    
    private void cleanupCaches() {
        long now = System.currentTimeMillis();
        verifiedCache.entrySet().removeIf(entry -> now > entry.getValue());
        blockedCache.entrySet().removeIf(entry -> now > entry.getValue());
        
        // Możemy też czyścić ipLocks z wygasłych wpisów, ale robimy to on-demand przy logowaniu
    }

    private void refreshBypassList() {
        String url = getConfig().getString("bypass-api.url");
        String apiKey = getConfig().getString("bypass-api.x-api-key");
        try {
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(url)).header("x-api-key", apiKey).timeout(Duration.ofSeconds(5)).GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                if (json.has("success") && json.get("success").getAsBoolean()) {
                    JsonArray ips = json.getAsJsonArray("ips");
                    Set<String> newSet = new HashSet<>();
                    ips.forEach(element -> newSet.add(element.getAsString()));
                    for (String ip : newSet) blockedCache.remove(ip);
                    Set<String> concurrentSet = ConcurrentHashMap.newKeySet();
                    concurrentSet.addAll(newSet);
                    this.cachedBypassIps = concurrentSet;
                }
            }
        } catch (Exception e) {
            getLogger().warning("Blad pobierania bypass IP: " + e.getMessage());
        }
    }

    private void checkOkaeri(AsyncPlayerPreLoginEvent event, String ip) {
        String baseUrl = getConfig().getString("okaeri.url");
        if (!baseUrl.endsWith("/")) baseUrl += "/";
        String token = getConfig().getString("okaeri.api-key");

        try {
            HttpRequest request = HttpRequest.newBuilder().uri(URI.create(baseUrl + ip)).header("Authorization", "Bearer " + token).timeout(Duration.ofSeconds(3)).GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonObject json = gson.fromJson(response.body(), JsonObject.class);
                boolean shouldBlock = json.getAsJsonObject("suggestions").get("block").getAsBoolean();

                if (shouldBlock) {
                    event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, color(getConfig().getString("messages.kick")));
                    long hours = getConfig().getInt("cache.duration-hours", 12);
                    blockedCache.put(ip, System.currentTimeMillis() + (hours * 3600000L));
                } else {
                    long hours = getConfig().getInt("cache.duration-hours", 12);
                    verifiedCache.put(ip, System.currentTimeMillis() + (hours * 3600000L));
                }
            } else if (!getConfig().getBoolean("okaeri.fail-open")) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, color(getConfig().getString("messages.error")));
            }
        } catch (Exception e) {
            if (!getConfig().getBoolean("okaeri.fail-open")) {
                event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, color(getConfig().getString("messages.error")));
            }
        }
    }

    private String color(String msg) {
        return ChatColor.translateAlternateColorCodes('&', msg);
    }
}
