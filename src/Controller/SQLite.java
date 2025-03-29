package Controller;

import Model.History;
import Model.Logs;
import Model.Product;
import Model.User;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.sql.*;  
import java.sql.PreparedStatement; 

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.Date;

public class SQLite {
    
    public int DEBUG_MODE = 0;
    String driverURL = "jdbc:sqlite:" + "database.db";
    
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 128;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    
    private String hashPassword(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
    
    // Method to validate if a username exists
    public boolean usernameExists(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return false;
    }
    
    public void createNewDatabase() {
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            if (conn != null) {
                DatabaseMetaData meta = conn.getMetaData();
                System.out.println("Database database.db created.");
            }
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void enableWALMode() {
        String query = "PRAGMA journal_mode=WAL;";

        try (Connection conn = DriverManager.getConnection(driverURL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(query);
            System.out.println("✅ SQLite WAL mode enabled!");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void createHistoryTable() {
        String sql = "CREATE TABLE IF NOT EXISTS history (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " username TEXT NOT NULL,\n"
            + " name TEXT NOT NULL,\n"
            + " stock INTEGER DEFAULT 0,\n"
            + " timestamp TEXT NOT NULL\n"
            + ");";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table history in database.db created.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void createLogsTable() {
        String sql = "CREATE TABLE IF NOT EXISTS logs (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " event TEXT NOT NULL,\n"
            + " username TEXT NOT NULL,\n"
            + " desc TEXT NOT NULL,\n"
            + " timestamp TEXT NOT NULL\n"
            + ");";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table logs in database.db created.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
     
    public void createProductTable() {
        String sql = "CREATE TABLE IF NOT EXISTS product (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " name TEXT NOT NULL UNIQUE,\n"
            + " stock INTEGER DEFAULT 0,\n"
            + " price REAL DEFAULT 0.00\n"
            + ");";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table product in database.db created.");
        } catch (Exception ex) {
            System.out.print(ex);
             System.out.println("❌ ERROR creating `users` table: " + ex.getMessage());
        }
    }
     
    public void createUserTable() {
        String sql = "CREATE TABLE IF NOT EXISTS users (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " username TEXT NOT NULL UNIQUE,\n"
                + " password TEXT NOT NULL,\n"
                + " salt TEXT NOT NULL,\n"
                + " role INTEGER DEFAULT 2,\n"
                + " failed_attempts INTEGER DEFAULT 0,\n"
                + " locked INTEGER DEFAULT 0\n"
                + ");";

        try (Connection conn = DriverManager.getConnection(driverURL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table users in database.db created.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void dropHistoryTable() {
        String sql = "DROP TABLE IF EXISTS history;";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table history in database.db dropped.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void dropLogsTable() {
        String sql = "DROP TABLE IF EXISTS logs;";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table logs in database.db dropped.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void dropProductTable() {
        String sql = "DROP TABLE IF EXISTS product;";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table product in database.db dropped.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void dropUserTable() {
        String sql = "DROP TABLE IF EXISTS users;";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table users in database.db dropped.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void addHistory(String username, String name, int stock, String timestamp) {
        String sql = "INSERT INTO history(username,name,stock,timestamp) VALUES('" + username + "','" + name + "','" + stock + "','" + timestamp + "')";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()){
            stmt.execute(sql);
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void addLogs(String event, String username, String desc, String timestamp) {
        String sql = "INSERT INTO logs(event,username,desc,timestamp) VALUES('" + event + "','" + username + "','" + desc + "','" + timestamp + "')";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()){
            stmt.execute(sql);
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public boolean addProduct(String username, String name, int stock, double price) {
    int role = getUserRole(username);

    if (role != 3 && role != 4) {
        System.out.println("Access Denied: Only staff and managers can add products.");
        return false;
    }

    String sql = "INSERT INTO product(name, stock, price) VALUES(?, ?, ?)";

    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, name);
        pstmt.setInt(2, stock);
        pstmt.setDouble(3, price); 
        pstmt.executeUpdate();
        System.out.println("Product added successfully.");
        return true;
    } catch (Exception ex) {
        ex.printStackTrace();
        return false;
    }
}

    
  public boolean updateProduct(String username, int id, String name, int stock, double price) {
    
    int role = getUserRole(username);

    if (role != 3 && role != 4) { 
        System.out.println("Access Denied: Only staff and managers can update products.");
        return false; 
    }
  
    String updateSql = "UPDATE product SET name = ?, stock = ?, price = ? WHERE id = ?";

    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
         
        pstmt.setString(1, name); 
        pstmt.setInt(2, stock);  
        pstmt.setDouble(3, price); 
        pstmt.setInt(4, id); 
        
        int rowsAffected = pstmt.executeUpdate();
        
        if (rowsAffected > 0) {
            System.out.println("Product updated successfully (ID: " + id + ")");
            return true; 
        } else {
            System.out.println("❌ No product found with ID: " + id);
            return false; 
        }

    } catch (SQLException ex) {
        ex.printStackTrace();
        return false; 
    }
}


    
    public boolean deleteProduct(String username, int id) {
        
    int role = getUserRole(username);

    if (role != 3 && role != 4) { 
        System.out.println("Access Denied: Only staff and managers can add products.");
        return false;
    }
    String sql = "DELETE FROM product WHERE id = ?";

    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setInt(1, id);
        int rowsAffected = pstmt.executeUpdate();
        
        if (rowsAffected > 0) {
            System.out.println("Product deleted successfully (ID: " + id + ")");
            return true;
        } else {
            System.out.println("No product found with ID: " + id);
            return false;
        }
    } catch (SQLException ex) {
        ex.printStackTrace();
        return false;

    }
}
    
    public int findProductIdByNameStockPrice(String name, int stock, double price) {
    String sql = "SELECT id FROM product WHERE name = ? AND stock = ? AND price = ?";
    
    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(sql)) {
        pstmt.setString(1, name);
        pstmt.setInt(2, stock);
        pstmt.setDouble(3, price);
        
        ResultSet rs = pstmt.executeQuery();
        if (rs.next()) {
            return rs.getInt("id"); 
        }
    } catch (SQLException ex) {
        ex.printStackTrace();
    }
    return -1; 
}
    
    public boolean addUser(String username, String password) {
        if (username == null || username.trim().isEmpty() || password == null || password.length() < 8) {
            return false;
        }

        if (usernameExists(username)) {
            return false;
        }

        String sql = "INSERT INTO users(username, password, salt) VALUES(?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            byte[] salt = generateSalt();
            String hashedPassword = hashPassword(password, salt);
            String saltStr = Base64.getEncoder().encodeToString(salt);

            pstmt.setString(1, username);
            pstmt.setString(2, hashedPassword);
            pstmt.setString(3, saltStr);
            pstmt.executeUpdate();

            // Add log entry
            addLogs("NOTICE", username, "User registration successful", new Timestamp(new Date().getTime()).toString());
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    public boolean updateUserRole(String username, int id, int newRole) {
    
    int role = getUserRole(username);

    if (role != 5) { 
        System.out.println("Access Denied: Only admin users can update roles.");
        return false;
    }

 
    String updateSql = "UPDATE users SET role = ? WHERE id = ?";

    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
        
 
        pstmt.setInt(1, newRole);
        pstmt.setInt(2, id); // Identify which user to update
        
        int rowsAffected = pstmt.executeUpdate();
        
        if (rowsAffected > 0) {
            System.out.println("✅ User role updated successfully (ID: " + id + ")");
            return true;
        } else {
            System.out.println("❌ No user found with ID: " + id);
            return false;
        }

    } catch (SQLException ex) {
        ex.printStackTrace();
        return false;
    }
}
    
    public int findUserIdByUsername(String username) {
    String query = "SELECT id FROM users WHERE username = ?";

    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(query)) {

        pstmt.setString(1, username);
        ResultSet rs = pstmt.executeQuery();

        if (rs.next()) {
            return rs.getInt("id"); // Return the user ID
        }

    } catch (SQLException ex) {
        ex.printStackTrace();
    }

    return -1; 
}
    
    public boolean updateUserPassword(String username, int id, String newPassword) {
    
    int role = getUserRole(username);

    if (role != 5) { 
        System.out.println("Access Denied: Only admin users can update roles.");
        return false; 
    }


    String updateSql = "UPDATE users SET password = ? WHERE id = ?";

    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(updateSql)) {
        
    
        pstmt.setString(1, newPassword);
        pstmt.setInt(2, id); 
        

        int rowsAffected = pstmt.executeUpdate();
        
        if (rowsAffected > 0) {
            System.out.println("Password updated successfully (ID: " + id + ")");
            return true;
        } else {
            System.out.println("No user found with ID: " + id);
            return false;
        }

    } catch (SQLException ex) {
        ex.printStackTrace();
        return false;
    }
}
    
    public boolean updateUserLockStatus(int userID, boolean lock) {
    String sql = "UPDATE users SET locked = ? WHERE id = ?";

    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(sql)) {

        pstmt.setInt(1, lock ? 1 : 0); // 1 = Locked, 0 = Unlocked
        pstmt.setInt(2, userID);

        int rowsAffected = pstmt.executeUpdate();

        return rowsAffected > 0;
    } catch (SQLException ex) {
        ex.printStackTrace();
        return false;
    }
}
    
    public boolean deleteUser(int userID) {
    String sql = "DELETE FROM users WHERE id = ?";

    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(sql)) {

        pstmt.setInt(1, userID);
        int rowsAffected = pstmt.executeUpdate();

        return rowsAffected > 0;
    } catch (SQLException ex) {
        ex.printStackTrace();
        return false;
    }
}
    
    public void clearLogs() {
    String query = "DELETE FROM logs";
    
    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(query)) {
         
        int rowsAffected = pstmt.executeUpdate();
        System.out.println("✅ Logs cleared. Rows affected: " + rowsAffected);
        
    } catch (SQLException e) {
        e.printStackTrace();
        System.out.println("❌ Failed to clear logs.");
    }
}
    
    public ArrayList<History> getHistory(){
        String sql = "SELECT id, username, name, stock, timestamp FROM history";
        ArrayList<History> histories = new ArrayList<History>();
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){
            
            while (rs.next()) {
                histories.add(new History(rs.getInt("id"),
                                   rs.getString("username"),
                                   rs.getString("name"),
                                   rs.getInt("stock"),
                                   rs.getString("timestamp")));
            }
        } catch (Exception ex) {
            System.out.print(ex);
        }
        return histories;
    }
    
    public ArrayList<Logs> getLogs(){
        String sql = "SELECT id, event, username, desc, timestamp FROM logs";
        ArrayList<Logs> logs = new ArrayList<Logs>();
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){
            
            while (rs.next()) {
                logs.add(new Logs(rs.getInt("id"),
                                   rs.getString("event"),
                                   rs.getString("username"),
                                   rs.getString("desc"),
                                   rs.getString("timestamp")));
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return logs;
    }
    
    public ArrayList<Product> getProduct(){
        String sql = "SELECT id, name, stock, price FROM product";
        ArrayList<Product> products = new ArrayList<Product>();
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){
            
            while (rs.next()) {
                products.add(new Product(rs.getInt("id"),
                                   rs.getString("name"),
                                   rs.getInt("stock"),
                                   rs.getFloat("price")));
            }
        } catch (Exception ex) {
            System.out.print(ex);
        }
        return products;
    }
    
    public ArrayList<User> getUsers(){
        String sql = "SELECT id, username, password, salt, role, locked FROM users";
        ArrayList<User> users = new ArrayList<User>();

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){

            while (rs.next()) {
                users.add(new User(rs.getInt("id"),
                                   rs.getString("username"),
                                   rs.getString("password"),
                                   rs.getString("salt"),
                                   rs.getInt("role"),
                                   rs.getInt("locked")));
            }
        } catch (Exception ex) {}
        return users;
    }
    
    public void addUser(String username, String password, int role) {
        String sql = "INSERT INTO users(username,password,role) VALUES('" + username + "','" + password + "','" + role + "')";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()){
            stmt.execute(sql);
            
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void removeUser(String username) {
        String sql = "DELETE FROM users WHERE username='" + username + "';";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("User " + username + " has been deleted.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public Product getProduct(String name){
        String sql = "SELECT name, stock, price FROM product WHERE name='" + name + "';";
        Product product = null;
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){
            product = new Product(rs.getString("name"),
                                   rs.getInt("stock"),
                                   rs.getFloat("price"));
        } catch (Exception ex) {
            System.out.print(ex);
        }
        return product;
    }
    
     public boolean authenticateUser(String username, String password) {
        if (isAccountLocked(username)) {
            System.out.println(" Account is locked: " + username);
            return false;
        }

        String sql = "SELECT password, salt FROM users WHERE username = ? AND locked = 0";
    
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedPassword = rs.getString("password");
                String salt = rs.getString("salt");
                byte[] saltBytes = Base64.getDecoder().decode(salt);

                String hashedPassword = hashPassword(password, saltBytes);

                if (storedPassword.equals(hashedPassword)) {
                    addLogs("LOGIN", username, "User login successful", new Timestamp(new Date().getTime()).toString());
                    resetFailedAttempts(username);
                    return true;
                } else {
                    addLogs("WARNING", username, "Failed login attempt", new Timestamp(new Date().getTime()).toString());
                    incrementFailedAttempts(username);
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return false;
    }

    public void incrementFailedAttempts(String username) {
      String query = "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?";

      try (Connection conn = DriverManager.getConnection(driverURL);
           PreparedStatement stmt = conn.prepareStatement(query)) {
          stmt.setString(1, username);
          stmt.executeUpdate();

          // Get current failed attempts
          int failedAttempts = getFailedAttempts(username);

          // If failed attempts reach 5, lock the account
          if (failedAttempts >= 5) {
              lockAccount(username);
          } else if (failedAttempts >= 3) { 
              int delay = (int) Math.pow(2, failedAttempts - 2);
              System.out.println("⚠️ Login delayed for " + delay + " seconds due to multiple failed attempts.");
              Thread.sleep(delay * 1000);
          }
      } catch (SQLException | InterruptedException e) {
          e.printStackTrace();
      }
    }


    private int getFailedAttempts(String username) {
        String query = "SELECT failed_attempts FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("failed_attempts");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0; 
    }
   
    public boolean isAccountLocked(String username) {
     String query = "SELECT failed_attempts, locked FROM users WHERE username = ?";

     try (Connection conn = DriverManager.getConnection(driverURL);
          PreparedStatement stmt = conn.prepareStatement(query)) {
         stmt.setString(1, username);
         ResultSet rs = stmt.executeQuery();

         if (rs.next()) {
             int failedAttempts = rs.getInt("failed_attempts");
             int locked = rs.getInt("locked");

             if (failedAttempts >= 5) {
                 lockAccount(username);  
                 return true;
             }
             return locked == 1; 
         }
     } catch (SQLException e) {
         e.printStackTrace();
     }
     return false;
    }
    
    

    public void lockAccount(String username) {
     String query = "UPDATE users SET locked = 1 WHERE username = ?";

     try (Connection conn = DriverManager.getConnection(driverURL);
          PreparedStatement stmt = conn.prepareStatement(query)) {
         stmt.setString(1, username);
         stmt.executeUpdate();
         System.out.println("Account locked for user: " + username);
     } catch (SQLException e) {
         e.printStackTrace();
     }
    }


    public void resetFailedAttempts(String username) {
        String query = "UPDATE users SET failed_attempts = 0 WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
            
        }  
    }
    
    public void addTestUser() {
     String username = "testuser";
     String password = "password123";  // Plaintext password for testing

     String sql = "INSERT INTO users (username, password, role, failed_attempts, locked) VALUES (?, ?, ?, 0, 0)";

     try (Connection conn = DriverManager.getConnection(driverURL);
          PreparedStatement stmt = conn.prepareStatement(sql)) {
         stmt.setString(1, username);
         stmt.setString(2, password);
         stmt.setInt(3, 2);  // Role 2 = Regular User (change as needed)
         stmt.executeUpdate();
         System.out.println("✅ Test user 'testuser' added successfully!");
     } catch (SQLException e) {
         if (e.getMessage().contains("UNIQUE constraint failed")) {
             System.out.println("⚠️ Test user 'testuser' already exists.");
         } else {
             e.printStackTrace();
         }
     }
    }  
    
    public int getUserRole(String username) {
    int role = -1; // Default value (invalid role)
    
    String query = "SELECT role FROM users WHERE username = ?"; 
    
    try (Connection conn = DriverManager.getConnection(driverURL);
         PreparedStatement pstmt = conn.prepareStatement(query)) {
        
        pstmt.setString(1, username);
        ResultSet rs = pstmt.executeQuery();

        if (rs.next()) {
            role = rs.getInt("role"); // Get role from database
        }
    } catch (SQLException e) {
        System.out.println("Error retrieving user role: " + e.getMessage());
    }
    
    return role;
}

}