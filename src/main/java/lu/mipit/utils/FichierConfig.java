package lu.mipit.utils;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;
import java.nio.file.Files;
import java.nio.file.Path;

public class FichierConfig {

    private static final Properties propConfig = new Properties();
    private static final String CONFIG_FILE_NAME = "config.properties";

    static {
        loadProperties();
    }

    private FichierConfig() {
        // Private constructor to prevent instantiation
    }

    private static void loadProperties() {
        Path configPath = Paths.get(getUserdir(), CONFIG_FILE_NAME);
        try (var inputStream = Files.newInputStream(configPath)) {
            propConfig.load(inputStream);
        } catch (IOException e) {
            // Consider using a logging framework here
            System.err.println("Error loading configuration: " + e.getMessage());
            throw new RuntimeException("Failed to load configuration", e);
        }
    }

    public static String getProperty(String key) {
        return propConfig.getProperty(key);
    }

    private static String getUserdir() {
        return System.getProperty("user.dir") + System.getProperty("file.separator")
                + "src" + System.getProperty("file.separator") + "main" + System.getProperty("file.separator") + "java" + System.getProperty("file.separator")
                + "lu" + System.getProperty("file.separator") + "mipit" + System.getProperty("file.separator")
                + "Utils" + System.getProperty("file.separator");
    }
}
