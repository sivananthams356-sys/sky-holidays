package com.skyholidays;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/api")
public class ApiController {

    private static final Logger log = LoggerFactory.getLogger(ApiController.class);
    private static final Map<String, String> KIND = Map.of("buses", "bus", "rooms", "room", "foods", "food", "places", "place");
    private static final Map<String, String> IMG_EXT = Map.of("image/jpeg", ".jpg", "image/png", ".png", "image/webp", ".webp");
    private static final Map<String, String> VID_EXT = Map.of("video/mp4", ".mp4", "video/webm", ".webm");
    private static final Map<String, String> TRIP_CATS = Map.of("honeymoon", "Honeymoon Trip", "stranger", "Stranger Trip", "family", "Family Trip", "school", "School Trip");
    private static final Pattern EMAIL = Pattern.compile("^\\S+@\\S+\\.\\S+$");

    public record AuthReq(String email, String password, String name, String phone) {}
    public record SettingsReq(String upi) {}
    public record EnqReq(String name, String mob, String msg) {}
    public record Line(String kind, Long item_id, Integer qty, Integer days) {}
    public record BookingReq(String kind, Long item_id, Integer qty, Integer days, String date, String pay_method, String pay_ref) {}
    public record TripBookReq(Integer people, String date, String pay_method, String pay_ref) {}
    public record TripRequestReq(String category, String location, String date, Integer people, String budget, String contact, String note) {}
    public record PackageReq(String date, String pay_method, String pay_ref, List<Line> lines) {}

    private record Priced(Long itemId, String name, int qty, int days, BigDecimal amount) {}
    private record Pay(String method, String status, String ref) {}
    private record Saved(String url, String kind) {}

    @Value("${app.upi-id:}")
    private String upiId;

    @Value("${app.debug-errors:true}")
    private boolean debugErrors;

    private final JdbcTemplate db;
    private final PasswordEncoder enc;
    private final TransactionTemplate tx;
    private final Path uploads;

    ApiController(JdbcTemplate db, PasswordEncoder enc, PlatformTransactionManager tm,
                  @Value("${app.upload-dir}") String dir) throws IOException {
        this.db = db;
        this.enc = enc;
        this.tx = new TransactionTemplate(tm);
        this.uploads = Paths.get(dir).toAbsolutePath().normalize();
        Files.createDirectories(uploads);
    }

    /* ---------------- helpers ---------------- */

    private static ResponseStatusException err(HttpStatus s, String m) { return new ResponseStatusException(s, m); }

    private static String kindOf(String plural) {
        String k = KIND.get(plural);
        if (k == null) throw err(HttpStatus.NOT_FOUND, "Unknown section.");
        return k;
    }

    private static AppUser me() {
        return (AppUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    private static Map<String, Object> pub(AppUser u) {
        return Map.of("id", u.id(), "name", u.name(), "email", u.email(), "role", u.role());
    }

    private static String clean(String s, int max) {
        if (s == null) return null;
        s = s.trim();
        if (s.isEmpty()) return null;
        return s.length() > max ? s.substring(0, max) : s;
    }

    private long insertId(String sql, Object... args) {
        KeyHolder kh = new GeneratedKeyHolder();
        db.update(con -> {
            PreparedStatement ps = con.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS);
            for (int i = 0; i < args.length; i++) ps.setObject(i + 1, args[i]);
            return ps;
        }, kh);
        Number n = kh.getKey();
        if (n == null) throw new IllegalStateException("No id returned");
        return n.longValue();
    }

    private void startSession(HttpServletRequest req, HttpServletResponse res, AppUser u) {
        if (req.getSession(false) != null) req.changeSessionId();
        var auth = UsernamePasswordAuthenticationToken.authenticated(
                u, null, List.of(new SimpleGrantedAuthority("ROLE_" + u.role().toUpperCase())));
        SecurityContext ctx = SecurityContextHolder.createEmptyContext();
        ctx.setAuthentication(auth);
        SecurityContextHolder.setContext(ctx);
        new HttpSessionSecurityContextRepository().saveContext(ctx, req, res);
    }

    /* ---------------- auth ---------------- */

    @PostMapping("/auth/signup")
    Map<String, Object> signup(@RequestBody AuthReq b, HttpServletRequest req, HttpServletResponse res) {
        String email = b.email() == null ? "" : b.email().trim().toLowerCase();
        String pw = b.password() == null ? "" : b.password();
        if (email.length() > 120 || !EMAIL.matcher(email).matches()) throw err(HttpStatus.BAD_REQUEST, "Enter a valid email address.");
        if (pw.length() < 6) throw err(HttpStatus.BAD_REQUEST, "Password needs at least 6 characters.");
        Integer n = db.queryForObject("SELECT COUNT(*) FROM users WHERE email=?", Integer.class, email);
        if (n != null && n > 0) throw err(HttpStatus.CONFLICT, "This email is already registered. Please log in.");
        String name = clean(b.name(), 60);
        if (name == null || name.length() < 2) throw err(HttpStatus.BAD_REQUEST, "Enter your full name.");
        String phone = b.phone() == null ? "" : b.phone().replaceAll("[\\s-]", "");
        if (!phone.matches("\\+?[0-9]{10,13}")) throw err(HttpStatus.BAD_REQUEST, "Enter a valid mobile number (10 digits).");
        db.update("INSERT INTO users (name,email,pass_hash,role,phone) VALUES (?,?,?,'client',?)", name, email, enc.encode(pw), phone);
        Long id = db.queryForObject("SELECT id FROM users WHERE email=?", Long.class, email);
        AppUser u = new AppUser(id, name, email, "client");
        startSession(req, res, u);
        return Map.of("user", pub(u));
    }

    @PostMapping("/auth/login")
    Map<String, Object> login(@RequestBody AuthReq b, HttpServletRequest req, HttpServletResponse res) {
        String email = b.email() == null ? "" : b.email().trim().toLowerCase();
        String pw = b.password() == null ? "" : b.password();
        List<Map<String, Object>> rows = db.queryForList("SELECT id,name,email,pass_hash,role FROM users WHERE email=?", email);
        if (rows.isEmpty() || !enc.matches(pw, (String) rows.get(0).get("pass_hash")))
            throw err(HttpStatus.UNAUTHORIZED, "Wrong email or password.");
        Map<String, Object> r = rows.get(0);
        AppUser u = new AppUser(((Number) r.get("id")).longValue(), (String) r.get("name"), (String) r.get("email"), (String) r.get("role"));
        startSession(req, res, u);
        return Map.of("user", pub(u));
    }

    @PostMapping("/auth/logout")
    Map<String, Object> logout(HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        if (s != null) s.invalidate();
        SecurityContextHolder.clearContext();
        return Map.of("ok", true);
    }

    @GetMapping("/me")
    Map<String, Object> whoAmI() {
        return Map.of("user", pub(me()));
    }

    /* ---------------- media helpers ---------------- */

    /** Adds a "media" list (photos / videos) to every row. ownerType is "item" or "experience". */
    private void attachMedia(List<Map<String, Object>> rows, String ownerType) {
        Map<Long, List<Map<String, Object>>> by = new HashMap<>();
        for (Map<String, Object> m : db.queryForList("SELECT id,owner_id,url,kind FROM media WHERE owner_type=? ORDER BY id", ownerType)) {
            long owner = ((Number) m.get("owner_id")).longValue();
            by.computeIfAbsent(owner, x -> new ArrayList<>()).add(Map.of("id", m.get("id"), "url", m.get("url"), "kind", m.get("kind")));
        }
        for (Map<String, Object> r : rows) {
            r.put("media", by.getOrDefault(((Number) r.get("id")).longValue(), List.of()));
        }
    }

    /** Checks every file first, then saves them. Photos up to 5 MB, videos up to 50 MB. */
    private List<Saved> saveFiles(MultipartFile[] files) throws IOException {
        List<MultipartFile> ok = new ArrayList<>();
        List<String> kinds = new ArrayList<>();
        List<String> exts = new ArrayList<>();
        if (files != null) {
            for (MultipartFile f : files) {
                if (f == null || f.isEmpty()) continue;
                String ct = f.getContentType();
                String kind = "image";
                String ext = IMG_EXT.get(ct);
                if (ext == null) { ext = VID_EXT.get(ct); kind = "video"; }
                if (ext == null) throw err(HttpStatus.BAD_REQUEST, "Only JPG, PNG, WEBP photos and MP4, WEBM videos are allowed.");
                long max = kind.equals("image") ? 5L * 1024 * 1024 : 50L * 1024 * 1024;
                if (f.getSize() > max) throw err(HttpStatus.BAD_REQUEST, kind.equals("image") ? "Each photo must be under 5 MB." : "Each video must be under 50 MB.");
                ok.add(f); kinds.add(kind); exts.add(ext);
            }
        }
        if (ok.size() > 9) throw err(HttpStatus.BAD_REQUEST, "Upload at most 9 files in one go.");
        List<Saved> out = new ArrayList<>();
        for (int i = 0; i < ok.size(); i++) {
            String name = UUID.randomUUID().toString().replace("-", "") + exts.get(i);
            ok.get(i).transferTo(uploads.resolve(name));
            out.add(new Saved("/uploads/" + name, kinds.get(i)));
        }
        return out;
    }

    private void deleteFile(String url) throws IOException {
        if (url == null || url.isBlank()) return;
        Files.deleteIfExists(uploads.resolve(Paths.get(url).getFileName().toString()));
    }

    private void removeMediaOf(String ownerType, long id) throws IOException {
        List<String> urls = db.queryForList("SELECT url FROM media WHERE owner_type=? AND owner_id=?", String.class, ownerType, id);
        db.update("DELETE FROM media WHERE owner_type=? AND owner_id=?", ownerType, id);
        for (String u : urls) deleteFile(u);
    }

    /* ---------------- public ---------------- */

    @GetMapping("/catalog")
    Map<String, Object> catalog() {
        List<Map<String, Object>> rows = db.queryForList("SELECT id,kind,name,type,loc,seats,price,status,img FROM items ORDER BY id");
        attachMedia(rows, "item");
        Map<String, Object> out = new LinkedHashMap<>();
        KIND.forEach((plural, k) -> out.put(plural, rows.stream().filter(r -> k.equals(r.get("kind"))).toList()));
        return out;
    }

    @GetMapping("/experiences")
    List<Map<String, Object>> experiences() {
        List<Map<String, Object>> rows = db.queryForList(
                "SELECT id,title,description,DATE_FORMAT(event_date,'%d %b %Y') AS event_label FROM experiences "
                        + "ORDER BY COALESCE(event_date, DATE(created_at)) DESC, id DESC");
        attachMedia(rows, "experience");
        return rows;
    }

    @PostMapping("/enquiries")
    Map<String, Object> enquiry(@RequestBody EnqReq b) {
        String name = clean(b.name(), 80), msg = clean(b.msg(), 2000);
        if (name == null || msg == null) throw err(HttpStatus.BAD_REQUEST, "Add your name and a message.");
        String mob = clean(b.mob(), 20);
        db.update("INSERT INTO enquiries (name,mobile,message) VALUES (?,?,?)", name, mob == null ? "" : mob, msg);
        return Map.of("ok", true);
    }

    @GetMapping("/config")
    Map<String, Object> config() {
        return Map.of("upi", currentUpi(), "qr", currentQr());
    }

    /** UPI ID saved by the admin in Settings (falls back to app.upi-id in application.properties). */
    private String currentUpi() {
        List<String> r = db.queryForList("SELECT sval FROM settings WHERE skey='upi_id'", String.class);
        if (!r.isEmpty() && r.get(0) != null) return r.get(0).trim();
        return upiId == null ? "" : upiId.trim();
    }

    /* ---------------- admin: items ---------------- */

    @PostMapping(value = "/admin/{kind}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    Map<String, Object> addItem(@PathVariable("kind") String kind,
                                @RequestParam(value = "name", required = false) String name,
                                @RequestParam(value = "type", required = false) String type,
                                @RequestParam(value = "loc", required = false) String loc,
                                @RequestParam(value = "seats", required = false) String seats,
                                @RequestParam(value = "price", required = false) String price) {
        String k = kindOf(kind);
        String nm = clean(name, 120);
        if (nm == null) throw err(HttpStatus.BAD_REQUEST, "Enter a name first.");
        String tp = clean(type, 60);
        if ("bus".equals(k) && tp == null)
            throw err(HttpStatus.BAD_REQUEST, "Enter the bus type (for example AC or Non-AC).");
        BigDecimal p = BigDecimal.ZERO;
        try { if (price != null && !price.isBlank()) p = new BigDecimal(price.trim()); }
        catch (NumberFormatException e) { throw err(HttpStatus.BAD_REQUEST, "Price must be a number."); }
        if (p.signum() < 0) throw err(HttpStatus.BAD_REQUEST, "Price cannot be negative.");
        Integer seatCount = null;
        try { if (seats != null && !seats.isBlank()) seatCount = Integer.parseInt(seats.trim()); }
        catch (NumberFormatException e) { throw err(HttpStatus.BAD_REQUEST, "Seats must be a whole number."); }

        long id = insertId("INSERT INTO items (kind,name,type,loc,seats,price) VALUES (?,?,?,?,?,?)",
                k, nm, tp, clean(loc, 120), seatCount, p);
        return Map.of("ok", true, "id", id);
    }

    @PatchMapping("/admin/{kind}/{id}/toggle")
    Map<String, Object> toggle(@PathVariable("kind") String kind, @PathVariable("id") long id) {
        db.update("UPDATE items SET status=IF(status='Available','Unavailable','Available') WHERE id=? AND kind=?", id, kindOf(kind));
        return Map.of("ok", true);
    }

    @DeleteMapping("/admin/{kind}/{id}")
    Map<String, Object> delete(@PathVariable("kind") String kind, @PathVariable("id") long id) throws IOException {
        String k = kindOf(kind);
        Integer n = db.queryForObject("SELECT COUNT(*) FROM items WHERE id=? AND kind=?", Integer.class, id, k);
        if (n == null || n == 0) throw err(HttpStatus.NOT_FOUND, "This item no longer exists.");
        List<String> old = db.queryForList("SELECT img FROM items WHERE id=? AND img IS NOT NULL", String.class, id);
        removeMediaOf("item", id);
        db.update("DELETE FROM items WHERE id=? AND kind=?", id, k);
        for (String u : old) deleteFile(u);
        return Map.of("ok", true);
    }

    /* ---------------- admin: photos and videos ---------------- */

    @PostMapping(value = "/admin/media/{ownerType}/{ownerId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    Map<String, Object> addMedia(@PathVariable("ownerType") String ownerType, @PathVariable("ownerId") long ownerId,
                                 @RequestParam(value = "files", required = false) MultipartFile[] files) throws IOException {
        String table = "item".equals(ownerType) ? "items" : "experience".equals(ownerType) ? "experiences" : "trip".equals(ownerType) ? "trips" : null;
        if (table == null) throw err(HttpStatus.NOT_FOUND, "Unknown owner.");
        Integer n = db.queryForObject("SELECT COUNT(*) FROM " + table + " WHERE id=?", Integer.class, ownerId);
        if (n == null || n == 0) throw err(HttpStatus.NOT_FOUND, "This item no longer exists.");
        List<Saved> saved = saveFiles(files);
        if (saved.isEmpty()) throw err(HttpStatus.BAD_REQUEST, "Choose at least one photo or video.");
        for (Saved s : saved)
            db.update("INSERT INTO media (owner_type,owner_id,url,kind) VALUES (?,?,?,?)", ownerType, ownerId, s.url(), s.kind());
        return Map.of("ok", true, "added", saved.size());
    }

    @DeleteMapping("/admin/media/{id}")
    Map<String, Object> deleteMedia(@PathVariable("id") long id) throws IOException {
        List<String> urls = db.queryForList("SELECT url FROM media WHERE id=?", String.class, id);
        db.update("DELETE FROM media WHERE id=?", id);
        for (String u : urls) deleteFile(u);
        return Map.of("ok", true);
    }

    /* ---------------- admin: experiences (past events / industrial visits) ---------------- */

    @PostMapping(value = "/admin/experiences", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    Map<String, Object> addExperience(@RequestParam(value = "title", required = false) String title,
                                      @RequestParam(value = "description", required = false) String description,
                                      @RequestParam(value = "event_date", required = false) String eventDate) {
        String t = clean(title, 120);
        if (t == null) throw err(HttpStatus.BAD_REQUEST, "Enter a title first.");
        LocalDate d = null;
        String ds = clean(eventDate, 10);
        if (ds != null) {
            try { d = LocalDate.parse(ds); }
            catch (DateTimeParseException e) { throw err(HttpStatus.BAD_REQUEST, "Pick a valid event date."); }
            if (d.isAfter(LocalDate.now())) throw err(HttpStatus.BAD_REQUEST, "Experiences are for past events. Pick today or an earlier date.");
        }
        long id = insertId("INSERT INTO experiences (title,description,event_date) VALUES (?,?,?)",
                t, clean(description, 4000), d == null ? null : Date.valueOf(d));
        return Map.of("ok", true, "id", id);
    }

    @DeleteMapping("/admin/experiences/{id}")
    Map<String, Object> deleteExperience(@PathVariable("id") long id) throws IOException {
        removeMediaOf("experience", id);
        db.update("DELETE FROM experiences WHERE id=?", id);
        return Map.of("ok", true);
    }

    /* ---------------- admin: settings, users, enquiries ---------------- */

    private String currentQr() {
        List<String> r = db.queryForList("SELECT sval FROM settings WHERE skey='qr_url'", String.class);
        return (r.isEmpty() || r.get(0) == null) ? "" : r.get(0).trim();
    }

    /** Admin uploads the payment QR image from GPay / PhonePe / Paytm. */
    @PostMapping(value = "/admin/settings/qr", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    Map<String, Object> saveQr(@RequestParam(value = "file", required = false) MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) throw err(HttpStatus.BAD_REQUEST, "Choose your QR image first.");
        String ext = IMG_EXT.get(file.getContentType());
        if (ext == null) throw err(HttpStatus.BAD_REQUEST, "QR must be a JPG, PNG or WEBP image.");
        if (file.getSize() > 5L * 1024 * 1024) throw err(HttpStatus.BAD_REQUEST, "QR image must be under 5 MB.");
        String name = "qr-" + UUID.randomUUID().toString().replace("-", "") + ext;
        file.transferTo(uploads.resolve(name));
        String old = currentQr();
        db.update("INSERT INTO settings (skey,sval) VALUES ('qr_url',?) ON DUPLICATE KEY UPDATE sval=VALUES(sval)", "/uploads/" + name);
        deleteFile(old);
        return Map.of("ok", true, "qr", "/uploads/" + name);
    }

    @DeleteMapping("/admin/settings/qr")
    Map<String, Object> removeQr() throws IOException {
        String old = currentQr();
        db.update("DELETE FROM settings WHERE skey='qr_url'");
        deleteFile(old);
        return Map.of("ok", true);
    }

    @PutMapping("/admin/settings")
    Map<String, Object> saveSettings(@RequestBody SettingsReq b) {
        String upi = b.upi() == null ? "" : b.upi().trim();
        if (!upi.isEmpty() && (upi.length() > 80 || !upi.matches("[A-Za-z0-9._-]{2,}@[A-Za-z][A-Za-z0-9]{1,}")))
            throw err(HttpStatus.BAD_REQUEST, "Enter a valid UPI ID, for example name@bank.");
        db.update("INSERT INTO settings (skey,sval) VALUES ('upi_id',?) ON DUPLICATE KEY UPDATE sval=VALUES(sval)", upi);
        return Map.of("ok", true, "upi", upi);
    }

    @GetMapping("/admin/users")
    List<Map<String, Object>> users() {
        return db.queryForList("SELECT name,email,phone FROM users WHERE role='client' ORDER BY id DESC");
    }

    @GetMapping("/admin/enquiries")
    List<Map<String, Object>> enquiries() {
        return db.queryForList("SELECT name,mobile AS mob,message AS msg,DATE_FORMAT(created_at,'%d %b %Y %H:%i') AS dt FROM enquiries ORDER BY id DESC");
    }

    /* ---------------- bookings ---------------- */

    @GetMapping("/bookings")
    List<Map<String, Object>> bookings() {
        AppUser u = me();
        boolean admin = "admin".equals(u.role());
        String sql = "SELECT b.id, u.name AS `user`, u.email, u.phone, b.item_name, b.qty, b.days, i.kind AS item_kind, b.group_id, "
                + "DATE_FORMAT(b.travel_date,'%d %b %Y') AS `date`, b.status, b.amount, b.pay_method, b.pay_status, b.pay_ref "
                + "FROM bookings b JOIN users u ON u.id=b.user_id LEFT JOIN items i ON i.id=b.item_id "
                + (admin ? "" : "WHERE b.user_id=? ") + "ORDER BY b.id DESC";
        List<Map<String, Object>> rows = admin ? db.queryForList(sql) : db.queryForList(sql, u.id());
        for (Map<String, Object> r : rows) {
            int days = ((Number) r.get("days")).intValue(), qty = ((Number) r.get("qty")).intValue();
            StringBuilder pkg = new StringBuilder(String.valueOf(r.get("item_name")));
            if (days > 1) pkg.append(" (").append(days).append("room".equals(r.get("item_kind")) ? " nights)" : " days)");
            if (qty > 1) pkg.append(" x").append(qty);
            r.put("pkg", pkg.toString());
            r.remove("item_name"); r.remove("qty"); r.remove("days"); r.remove("item_kind");
        }
        return rows;
    }

    private LocalDate validDate(String s) {
        LocalDate d;
        try { d = LocalDate.parse(String.valueOf(s)); }
        catch (DateTimeParseException e) { throw err(HttpStatus.BAD_REQUEST, "Pick a valid date."); }
        LocalDate today = LocalDate.now();
        if (d.isBefore(today)) throw err(HttpStatus.BAD_REQUEST, "Past dates are not allowed. Pick today or a future date.");
        if (d.isAfter(today.plusYears(1))) throw err(HttpStatus.BAD_REQUEST, "Bookings are open only for the next 12 months.");
        return d;
    }

    private Pay payment(String methodIn, String refIn) {
        String method = methodIn == null ? "" : methodIn;
        String ref = clean(refIn, 40);
        if (method.equals("UPI")) {
            if (currentUpi().isBlank() && currentQr().isBlank()) throw err(HttpStatus.BAD_REQUEST, "UPI payment is not available right now. Choose pay at arrival.");
            if (ref == null || !ref.matches("[A-Za-z0-9]{8,30}")) throw err(HttpStatus.BAD_REQUEST, "Enter the UPI transaction / UTR ID (8-30 letters or numbers).");
            Integer used = db.queryForObject("SELECT COUNT(*) FROM bookings WHERE pay_ref=?", Integer.class, ref);
            if (used != null && used > 0) throw err(HttpStatus.CONFLICT, "This transaction ID is already used for another booking.");
            return new Pay("UPI", "Verification Pending", ref);
        }
        if (method.equals("Cash")) return new Pay("Cash", "Unpaid", null);
        throw err(HttpStatus.BAD_REQUEST, "Choose a payment method.");
    }

    /** Checks one booking line and works out its price on the server. */
    private Priced priceLine(Line l) {
        String k = l.kind() == null ? null : KIND.get(l.kind());
        if (k == null) throw err(HttpStatus.BAD_REQUEST, "Unknown booking type.");
        boolean bus = "bus".equals(k), room = "room".equals(k);
        int qty = bus ? 1 : (l.qty() == null ? 0 : l.qty());
        int days = (bus || room) ? (l.days() == null ? 1 : l.days()) : 1;
        if (qty < 1 || qty > 100) throw err(HttpStatus.BAD_REQUEST, "Enter a number between 1 and 100.");
        if (days < 1 || days > 60) throw err(HttpStatus.BAD_REQUEST, "Days / nights must be between 1 and 60.");
        if (l.item_id() == null) throw err(HttpStatus.NOT_FOUND, "This item no longer exists.");
        List<Map<String, Object>> rows = db.queryForList("SELECT id,name,price,status FROM items WHERE id=? AND kind=?", l.item_id(), k);
        if (rows.isEmpty()) throw err(HttpStatus.NOT_FOUND, "This item no longer exists.");
        String name = String.valueOf(rows.get(0).get("name"));
        if (!"Available".equals(rows.get(0).get("status"))) throw err(HttpStatus.CONFLICT, name + " is not available right now.");
        BigDecimal price = (bus || "place".equals(k)) ? BigDecimal.ZERO : new BigDecimal(String.valueOf(rows.get(0).get("price")));
        return new Priced(l.item_id(), name, qty, days, price.multiply(BigDecimal.valueOf((long) qty * days)));
    }

    private void insertBooking(long userId, Priced p, LocalDate d, Pay pay, String groupId) {
        db.update("INSERT INTO bookings (user_id,item_id,item_name,qty,days,travel_date,amount,pay_method,pay_status,pay_ref,group_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                userId, p.itemId(), p.name(), p.qty(), p.days(), Date.valueOf(d), p.amount(), pay.method(), pay.status(), pay.ref(), groupId);
    }

    private void requireCustomer() {
        if ("admin".equals(me().role()))
            throw err(HttpStatus.BAD_REQUEST, "The admin account cannot place bookings. Please log in with a customer account.");
    }

    @DeleteMapping("/admin/bookings/{id}")
    Map<String, Object> deleteBooking(@PathVariable("id") long id) {
        db.update("DELETE FROM bookings WHERE id=?", id);
        return Map.of("ok", true);
    }

    @PostMapping("/bookings")
    Map<String, Object> book(@RequestBody BookingReq b) {
        requireCustomer();
        LocalDate d = validDate(b.date());
        Priced p = priceLine(new Line(b.kind(), b.item_id(), b.qty(), b.days()));
        Pay pay = payment(b.pay_method(), b.pay_ref());
        if ("UPI".equals(pay.method()) && p.amount().signum() == 0)
            throw err(HttpStatus.BAD_REQUEST, "There is no amount to pay online. Choose pay at arrival.");
        insertBooking(me().id(), p, d, pay, null);
        return Map.of("ok", true, "amount", p.amount());
    }

    /** One click: bus + room + food/hotel + place with a single payment. */
    @PostMapping("/bookings/package")
    Map<String, Object> bookPackage(@RequestBody PackageReq b) {
        requireCustomer();
        LocalDate d = validDate(b.date());
        if (b.lines() == null || b.lines().isEmpty()) throw err(HttpStatus.BAD_REQUEST, "Select at least one item for your trip.");
        if (b.lines().size() > 8) throw err(HttpStatus.BAD_REQUEST, "A trip can have at most 8 items.");
        Pay pay = payment(b.pay_method(), b.pay_ref());
        List<Priced> items = new ArrayList<>();
        BigDecimal total = BigDecimal.ZERO;
        for (Line l : b.lines()) {
            Priced p = priceLine(l);
            items.add(p);
            total = total.add(p.amount());
        }
        if ("UPI".equals(pay.method()) && total.signum() == 0)
            throw err(HttpStatus.BAD_REQUEST, "There is no amount to pay online. Choose pay at arrival.");
        String group = UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        long uid = me().id();
        tx.executeWithoutResult(status -> {
            for (Priced p : items) insertBooking(uid, p, d, pay, group);
        });
        return Map.of("ok", true, "amount", total, "trip", group);
    }

    /** Updates one booking, or every booking of the same trip when it belongs to a package. */
    private void updateBookingOrTrip(String column, String value, long id) {
        List<String> g = db.queryForList("SELECT group_id FROM bookings WHERE id=? AND group_id IS NOT NULL", String.class, id);
        if (g.isEmpty()) db.update("UPDATE bookings SET " + column + "=? WHERE id=?", value, id);
        else db.update("UPDATE bookings SET " + column + "=? WHERE group_id=?", value, g.get(0));
    }

    @PatchMapping("/bookings/{id}/paid")
    Map<String, Object> markPaid(@PathVariable("id") long id) {
        updateBookingOrTrip("pay_status", "Paid", id);
        return Map.of("ok", true);
    }

    @PatchMapping("/bookings/{id}/confirm")
    Map<String, Object> confirm(@PathVariable("id") long id) {
        updateBookingOrTrip("status", "Confirmed", id);
        return Map.of("ok", true);
    }

    /* ---------------- trip types: honeymoon, stranger, family, school ---------------- */

    @GetMapping("/trips")
    List<Map<String, Object>> trips() {
        List<Map<String, Object>> rows = db.queryForList(
                "SELECT id,category,title,location,amount,contact,DATE_FORMAT(trip_date,'%d %b %Y') AS date_label, "
                        + "DATE_FORMAT(trip_date,'%Y-%m-%d') AS trip_date, description, status FROM trips ORDER BY id DESC");
        attachMedia(rows, "trip");
        return rows;
    }

    @PostMapping(value = "/admin/trips", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    Map<String, Object> addTrip(@RequestParam(value = "category", required = false) String category,
                                @RequestParam(value = "title", required = false) String title,
                                @RequestParam(value = "location", required = false) String location,
                                @RequestParam(value = "amount", required = false) String amount,
                                @RequestParam(value = "contact", required = false) String contact,
                                @RequestParam(value = "trip_date", required = false) String tripDate,
                                @RequestParam(value = "description", required = false) String description) {
        if (category == null || !TRIP_CATS.containsKey(category)) throw err(HttpStatus.BAD_REQUEST, "Choose the trip type.");
        String t = clean(title, 120);
        if (t == null) throw err(HttpStatus.BAD_REQUEST, "Enter a title first.");
        String loc = clean(location, 120);
        if (loc == null) throw err(HttpStatus.BAD_REQUEST, "Enter the location.");
        BigDecimal amt = BigDecimal.ZERO;
        try { if (amount != null && !amount.isBlank()) amt = new BigDecimal(amount.trim()); }
        catch (NumberFormatException e) { throw err(HttpStatus.BAD_REQUEST, "Amount must be a number."); }
        if (amt.signum() < 0) throw err(HttpStatus.BAD_REQUEST, "Amount cannot be negative.");
        String con = contact == null ? "" : contact.replaceAll("[\\s-]", "");
        if (!con.isEmpty() && !con.matches("\\+?[0-9]{10,13}")) throw err(HttpStatus.BAD_REQUEST, "Enter a valid contact number (10 digits).");
        if ("stranger".equals(category) && con.isEmpty()) throw err(HttpStatus.BAD_REQUEST, "Stranger trips need a contact number.");
        LocalDate d = null;
        String ds = clean(tripDate, 10);
        if (ds != null) {
            try { d = LocalDate.parse(ds); }
            catch (DateTimeParseException e) { throw err(HttpStatus.BAD_REQUEST, "Pick a valid trip date."); }
            if (d.isBefore(LocalDate.now())) throw err(HttpStatus.BAD_REQUEST, "The trip date cannot be in the past.");
        }
        long id = insertId("INSERT INTO trips (category,title,location,amount,contact,trip_date,description) VALUES (?,?,?,?,?,?,?)",
                category, t, loc, amt, con.isEmpty() ? null : con, d == null ? null : Date.valueOf(d), clean(description, 4000));
        return Map.of("ok", true, "id", id);
    }

    @PatchMapping("/admin/trips/{id}/toggle")
    Map<String, Object> toggleTrip(@PathVariable("id") long id) {
        db.update("UPDATE trips SET status=IF(status='Available','Unavailable','Available') WHERE id=?", id);
        return Map.of("ok", true);
    }

    @DeleteMapping("/admin/trips/{id}")
    Map<String, Object> deleteTrip(@PathVariable("id") long id) throws IOException {
        removeMediaOf("trip", id);
        db.update("DELETE FROM trips WHERE id=?", id);
        return Map.of("ok", true);
    }

    /** Customer books a ready-made trip package (amount x people). */
    @PostMapping("/trips/{id}/book")
    Map<String, Object> bookTrip(@PathVariable("id") long id, @RequestBody TripBookReq b) {
        requireCustomer();
        List<Map<String, Object>> rows = db.queryForList("SELECT id,category,title,amount,status,trip_date FROM trips WHERE id=?", id);
        if (rows.isEmpty()) throw err(HttpStatus.NOT_FOUND, "This trip no longer exists.");
        Map<String, Object> t = rows.get(0);
        if (!"Available".equals(t.get("status"))) throw err(HttpStatus.CONFLICT, "This trip is not available right now.");
        LocalDate d;
        if (t.get("trip_date") != null) {
            d = LocalDate.parse(String.valueOf(t.get("trip_date")));
            if (d.isBefore(LocalDate.now())) throw err(HttpStatus.CONFLICT, "The date of this trip has already passed.");
        } else {
            d = validDate(b.date());
        }
        int people = b.people() == null ? 0 : b.people();
        if (people < 1 || people > 500) throw err(HttpStatus.BAD_REQUEST, "Enter a number of people between 1 and 500.");
        Pay pay = payment(b.pay_method(), b.pay_ref());
        BigDecimal amount = new BigDecimal(String.valueOf(t.get("amount"))).multiply(BigDecimal.valueOf(people));
        if ("UPI".equals(pay.method()) && amount.signum() == 0)
            throw err(HttpStatus.BAD_REQUEST, "There is no amount to pay online. Choose pay at arrival.");
        String label = TRIP_CATS.get(String.valueOf(t.get("category"))) + ": " + t.get("title");
        if (label.length() > 120) label = label.substring(0, 120);
        insertBooking(me().id(), new Priced(null, label, people, 1, amount), d, pay, null);
        return Map.of("ok", true, "amount", amount);
    }

    /** Custom trip request (any location). The admin calls the customer back. */
    @PostMapping("/trip-requests")
    Map<String, Object> tripRequest(@RequestBody TripRequestReq b) {
        requireCustomer();
        if (b.category() == null || !TRIP_CATS.containsKey(b.category())) throw err(HttpStatus.BAD_REQUEST, "Choose the trip type.");
        String loc = clean(b.location(), 120);
        if (loc == null || loc.length() < 2) throw err(HttpStatus.BAD_REQUEST, "Enter the location you want to visit.");
        LocalDate d = validDate(b.date());
        int people = b.people() == null ? 0 : b.people();
        if (people < 1 || people > 1000) throw err(HttpStatus.BAD_REQUEST, "Enter the number of people.");
        BigDecimal budget = null;
        String bs = clean(b.budget(), 12);
        if (bs != null) {
            try { budget = new BigDecimal(bs); }
            catch (NumberFormatException e) { throw err(HttpStatus.BAD_REQUEST, "Budget must be a number."); }
            if (budget.signum() < 0) throw err(HttpStatus.BAD_REQUEST, "Budget cannot be negative.");
        }
        String contact = b.contact() == null ? "" : b.contact().replaceAll("[\\s-]", "");
        if (!contact.matches("\\+?[0-9]{10,13}")) throw err(HttpStatus.BAD_REQUEST, "Enter a valid contact number (10 digits).");
        db.update("INSERT INTO trip_requests (user_id,category,location,travel_date,people,budget,contact,note) VALUES (?,?,?,?,?,?,?,?)",
                me().id(), b.category(), loc, Date.valueOf(d), people, budget, contact, clean(b.note(), 1000));
        return Map.of("ok", true);
    }

    @GetMapping("/trip-requests")
    List<Map<String, Object>> tripRequests() {
        AppUser u = me();
        boolean admin = "admin".equals(u.role());
        String sql = "SELECT r.id, r.category, r.location, DATE_FORMAT(r.travel_date,'%d %b %Y') AS date_label, r.people, r.budget, "
                + "r.contact, r.note, r.status, u.name, u.email, u.phone FROM trip_requests r JOIN users u ON u.id=r.user_id "
                + (admin ? "" : "WHERE r.user_id=? ") + "ORDER BY r.id DESC";
        return admin ? db.queryForList(sql) : db.queryForList(sql, u.id());
    }

    @PatchMapping("/admin/trip-requests/{id}/contacted")
    Map<String, Object> requestContacted(@PathVariable("id") long id) {
        db.update("UPDATE trip_requests SET status='Contacted' WHERE id=?", id);
        return Map.of("ok", true);
    }

    /* ---------------- errors as {"error": "..."} ---------------- */

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, String>> onStatus(ResponseStatusException e) {
        return ResponseEntity.status(e.getStatusCode()).body(Map.of("error", e.getReason() == null ? "Error" : e.getReason()));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ResponseEntity<Map<String, String>> tooBig(MaxUploadSizeExceededException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "Upload is too large. Photos: max 5 MB each, videos: max 50 MB each."));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<Map<String, String>> badBody(HttpMessageNotReadableException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid request."));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String, String>> other(Exception e) {
        log.error("Unexpected error", e);
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) root = root.getCause();
        String detail = root.getClass().getSimpleName() + ": " + root.getMessage();
        if (detail.length() > 300) detail = detail.substring(0, 300);
        // While testing, the real reason is shown on screen. Set app.debug-errors=false in application.properties before going live.
        String msg = debugErrors ? "Server error: " + detail : "Server error. Please try again.";
        return ResponseEntity.status(500).body(Map.of("error", msg));
    }
}