package com.skyholidays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
public class AppConfig implements WebMvcConfigurer {

    @Value("${app.upload-dir}")
    private String uploadDir;

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** Public pages + login are open. /api/admin/** and booking confirm need the admin role. Everything else under /api needs login. */
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // Session cookie is SameSite=Lax (see application.properties), so CSRF token is not used for this same-origin app.
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/api/auth/**", "/api/catalog", "/api/enquiries", "/api/experiences", "/api/trips").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/api/bookings/*/confirm").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/api/bookings/*/paid").hasRole("ADMIN")
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) -> json(res, 401, "Please log in."))
                        .accessDeniedHandler((req, res, ex) -> json(res, 403, "Admin access only. You are logged in as " + who())));
        return http.build();
    }

    private static String who() {
        var a = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (a != null && a.getPrincipal() instanceof AppUser u)
            return (u.email() + " (" + u.role() + ")").replace("\\", "").replace("\"", "");
        return "unknown";
    }

    private static void json(jakarta.servlet.http.HttpServletResponse res, int code, String msg) throws IOException {
        res.setStatus(code);
        res.setContentType("application/json;charset=UTF-8");
        res.getWriter().write("{\"error\":\"" + msg + "\"}");
    }

    /** Serves uploaded photos at /uploads/... */
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        try {
            Path dir = Paths.get(uploadDir).toAbsolutePath().normalize();
            Files.createDirectories(dir);
            String loc = dir.toUri().toString();
            if (!loc.endsWith("/")) loc += "/";
            registry.addResourceHandler("/uploads/**").addResourceLocations(loc);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create upload folder", e);
        }
    }

    /** Creates missing tables / columns automatically, so nothing has to be run by hand in Workbench. */
    private static void migrate(JdbcTemplate db) {
        db.execute("CREATE TABLE IF NOT EXISTS bookings (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, item_id INT NULL, "
                + "item_name VARCHAR(120) NOT NULL, qty INT NOT NULL DEFAULT 1, travel_date DATE NOT NULL, "
                + "status ENUM('Pending','Confirmed','Cancelled') NOT NULL DEFAULT 'Pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                + "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (item_id) REFERENCES items(id) ON DELETE SET NULL)");
        db.execute("CREATE TABLE IF NOT EXISTS enquiries (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(80) NOT NULL, "
                + "mobile VARCHAR(20) DEFAULT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
        db.execute("CREATE TABLE IF NOT EXISTS settings (skey VARCHAR(50) PRIMARY KEY, sval VARCHAR(200) NOT NULL)");
        db.execute("CREATE TABLE IF NOT EXISTS media (id INT AUTO_INCREMENT PRIMARY KEY, owner_type VARCHAR(12) NOT NULL, owner_id INT NOT NULL, "
                + "url VARCHAR(200) NOT NULL, kind VARCHAR(8) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX (owner_type, owner_id))");
        db.execute("CREATE TABLE IF NOT EXISTS experiences (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(120) NOT NULL, description TEXT, "
                + "event_date DATE NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
        addColumn(db, "bookings", "group_id", "VARCHAR(20) DEFAULT NULL");
        db.execute("CREATE TABLE IF NOT EXISTS trips (id INT AUTO_INCREMENT PRIMARY KEY, category VARCHAR(12) NOT NULL, title VARCHAR(120) NOT NULL, "
                + "location VARCHAR(120) NOT NULL, amount DECIMAL(10,2) NOT NULL DEFAULT 0, contact VARCHAR(20) NULL, trip_date DATE NULL, "
                + "description TEXT, status VARCHAR(12) NOT NULL DEFAULT 'Available', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)");
        db.execute("CREATE TABLE IF NOT EXISTS trip_requests (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, category VARCHAR(12) NOT NULL, "
                + "location VARCHAR(120) NOT NULL, travel_date DATE NOT NULL, people INT NOT NULL, budget DECIMAL(10,2) NULL, contact VARCHAR(20) NOT NULL, "
                + "note TEXT, status VARCHAR(12) NOT NULL DEFAULT 'New', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                + "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)");
        addColumn(db, "users", "phone", "VARCHAR(20) DEFAULT NULL");
        addColumn(db, "bookings", "days", "INT NOT NULL DEFAULT 1");
        addColumn(db, "bookings", "amount", "DECIMAL(10,2) NOT NULL DEFAULT 0");
        addColumn(db, "bookings", "pay_method", "VARCHAR(20) NOT NULL DEFAULT 'Cash'");
        addColumn(db, "bookings", "pay_status", "VARCHAR(30) NOT NULL DEFAULT 'Unpaid'");
        addColumn(db, "bookings", "pay_ref", "VARCHAR(40) DEFAULT NULL");
    }

    private static void addColumn(JdbcTemplate db, String table, String column, String definition) {
        Integer n = db.queryForObject("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?",
                Integer.class, table, column);
        if (n != null && n == 0) {
            db.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition);
            System.out.println("Database updated: added " + table + "." + column);
        }
    }

    /** Creates / updates the admin account from application.properties on every start. */
    @Bean
    ApplicationRunner seedAdmin(JdbcTemplate db, PasswordEncoder enc,
                                @Value("${app.admin.email}") String email,
                                @Value("${app.admin.password}") String password) {
        return args -> {
            migrate(db);
            if (email.isBlank() || password.isBlank()) {
                System.out.println("app.admin.email / app.admin.password not set: no admin created.");
                return;
            }
            db.update("INSERT INTO users (name,email,pass_hash,role) VALUES ('Admin',?,?,'admin') "
                            + "ON DUPLICATE KEY UPDATE pass_hash=VALUES(pass_hash), role='admin'",
                    email.toLowerCase(), enc.encode(password));
            System.out.println("Admin account ready: " + email);
        };
    }
}