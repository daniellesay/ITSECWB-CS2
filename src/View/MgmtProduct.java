/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package View;

import Controller.SQLite;
import Model.Product;
import java.util.ArrayList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author beepxD
 */
public class MgmtProduct extends javax.swing.JPanel {

    public SQLite sqlite;
    public DefaultTableModel tableModel;
    
    public MgmtProduct(SQLite sqlite) {
        initComponents();
        this.sqlite = sqlite;
        tableModel = (DefaultTableModel)table.getModel();
        table.getTableHeader().setFont(new java.awt.Font("SansSerif", java.awt.Font.BOLD, 14));

//        UNCOMMENT TO DISABLE BUTTONS
        purchaseBtn.setVisible(false);
//        addBtn.setVisible(false);
//        editBtn.setVisible(false);
//        deleteBtn.setVisible(false);
    }

    public void init(){
        //      CLEAR TABLE
        for(int nCtr = tableModel.getRowCount(); nCtr > 0; nCtr--){
            tableModel.removeRow(0);
        }
        
//      LOAD CONTENTS
        ArrayList<Product> products = sqlite.getProduct();
        for(int nCtr = 0; nCtr < products.size(); nCtr++){
            tableModel.addRow(new Object[]{
                products.get(nCtr).getName(), 
                products.get(nCtr).getStock(), 
                products.get(nCtr).getPrice()});
        }
    }
    
    public void designer(JTextField component, String text){
        component.setSize(70, 600);
        component.setFont(new java.awt.Font("Tahoma", 0, 18));
        component.setBackground(new java.awt.Color(240, 240, 240));
        component.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        component.setBorder(javax.swing.BorderFactory.createTitledBorder(new javax.swing.border.LineBorder(new java.awt.Color(0, 0, 0), 2, true), text, javax.swing.border.TitledBorder.CENTER, javax.swing.border.TitledBorder.DEFAULT_POSITION, new java.awt.Font("Tahoma", 0, 12)));
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        table = new javax.swing.JTable();
        purchaseBtn = new javax.swing.JButton();
        addBtn = new javax.swing.JButton();
        editBtn = new javax.swing.JButton();
        deleteBtn = new javax.swing.JButton();

        table.setFont(new java.awt.Font("SansSerif", 0, 14)); // NOI18N
        table.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null},
                {null, null, null},
                {null, null, null},
                {null, null, null}
            },
            new String [] {
                "Name", "Stock", "Price"
            }
        ) {
            boolean[] canEdit = new boolean [] {
                false, false, false
            };

            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return canEdit [columnIndex];
            }
        });
        table.setRowHeight(24);
        table.getTableHeader().setReorderingAllowed(false);
        jScrollPane1.setViewportView(table);
        if (table.getColumnModel().getColumnCount() > 0) {
            table.getColumnModel().getColumn(0).setMinWidth(50);
            table.getColumnModel().getColumn(1).setMaxWidth(100);
            table.getColumnModel().getColumn(2).setMaxWidth(100);
        }

        purchaseBtn.setBackground(new java.awt.Color(255, 255, 255));
        purchaseBtn.setFont(new java.awt.Font("Tahoma", 1, 14)); // NOI18N
        purchaseBtn.setText("PURCHASE");
        purchaseBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                purchaseBtnActionPerformed(evt);
            }
        });

        addBtn.setBackground(new java.awt.Color(255, 255, 255));
        addBtn.setFont(new java.awt.Font("Tahoma", 1, 14)); // NOI18N
        addBtn.setText("ADD");
        addBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addBtnActionPerformed(evt);
            }
        });

        editBtn.setBackground(new java.awt.Color(255, 255, 255));
        editBtn.setFont(new java.awt.Font("Tahoma", 1, 14)); // NOI18N
        editBtn.setText("EDIT");
        editBtn.setToolTipText("");
        editBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editBtnActionPerformed(evt);
            }
        });

        deleteBtn.setBackground(new java.awt.Color(255, 255, 255));
        deleteBtn.setFont(new java.awt.Font("Tahoma", 1, 14)); // NOI18N
        deleteBtn.setText("DELETE");
        deleteBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                deleteBtnActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(0, 0, 0)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(purchaseBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGap(0, 0, 0)
                        .addComponent(addBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGap(0, 0, 0)
                        .addComponent(editBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGap(0, 0, 0)
                        .addComponent(deleteBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(jScrollPane1))
                .addGap(0, 0, 0))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(0, 0, 0)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 222, Short.MAX_VALUE)
                .addGap(0, 0, 0)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(deleteBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(addBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(purchaseBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(editBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE)))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void purchaseBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_purchaseBtnActionPerformed
        if(table.getSelectedRow() >= 0){
            JTextField stockFld = new JTextField("0");
            designer(stockFld, "PRODUCT STOCK");

            Object[] message = {
                "How many " + tableModel.getValueAt(table.getSelectedRow(), 0) + " do you want to purchase?", stockFld
            };

            int result = JOptionPane.showConfirmDialog(null, message, "PURCHASE PRODUCT", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null);

            if (result == JOptionPane.OK_OPTION) {
                System.out.println(stockFld.getText());
            }
        }
    }//GEN-LAST:event_purchaseBtnActionPerformed

    private void addBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addBtnActionPerformed
        // Create JTextFields for user input
    JTextField nameFld = new JTextField();
    JTextField stockFld = new JTextField();
    JTextField priceFld = new JTextField();

    // Call your designer method to customize JTextFields
    designer(nameFld, "PRODUCT NAME");
    designer(stockFld, "PRODUCT STOCK");
    designer(priceFld, "PRODUCT PRICE");

    // Prepare the message for the dialog
    Object[] message = {
        "Insert New Product Details:", nameFld, stockFld, priceFld
    };

    // Show the dialog and get the user's action
    int result = JOptionPane.showConfirmDialog(null, message, "ADD PRODUCT", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null);

    if (result == JOptionPane.OK_OPTION) {
        // Get the values entered by the user
        String name = nameFld.getText();
        String stockStr = stockFld.getText();
        String priceStr = priceFld.getText();
  

        // Convert stock and price to appropriate types (handle possible exceptions)
        try {
            int stock = Integer.parseInt(stockStr);  // Convert stock to integer
            double price = Double.parseDouble(priceStr);  // Convert price to double
     
            // Call the addProduct method from SQLite class
     
            String username = Login.loggedInUsername;
            sqlite.addProduct(username, name, stock, price); 

            // Optionally print values to the console for debugging
            System.out.println("Product Name: " + name);
            System.out.println("Stock: " + stock);
            System.out.println("Price: " + price);

        } catch (NumberFormatException e) {
            // Handle invalid input (e.g., if stock or price is not a number)
            JOptionPane.showMessageDialog(null, "Please enter valid numbers for stock and price.", "Invalid Input", JOptionPane.ERROR_MESSAGE);
        }
    }
        
    }//GEN-LAST:event_addBtnActionPerformed

    private void editBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editBtnActionPerformed
           if (table.getSelectedRow() >= 0) {

        // Retrieve the visible data from the selected row
        String name = (String) tableModel.getValueAt(table.getSelectedRow(), 0);
        int stock = (int) tableModel.getValueAt(table.getSelectedRow(), 1);
        Float priceFloat = (Float) tableModel.getValueAt(table.getSelectedRow(), 2);
        double price = priceFloat.doubleValue();

        // Create editable fields with current values
        JTextField nameFld = new JTextField(name);
        JTextField stockFld = new JTextField(String.valueOf(stock));
        JTextField priceFld = new JTextField(String.valueOf(price));

        // Design the text fields
        designer(nameFld, "PRODUCT NAME");
        designer(stockFld, "PRODUCT STOCK");
        designer(priceFld, "PRODUCT PRICE");

        // Prepare message with fields
        Object[] message = {
            "Edit Product Details:", nameFld, stockFld, priceFld
        };

        // Show dialog to the user
        int result = JOptionPane.showConfirmDialog(null, message, "EDIT PRODUCT", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        // Proceed if the user clicks OK
        if (result == JOptionPane.OK_OPTION) {
            // Get updated values from the input fields
            String updatedName = nameFld.getText();
            int updatedStock = Integer.parseInt(stockFld.getText());
            double updatedPrice = Double.parseDouble(priceFld.getText());

            // Find the product ID based on the selected row data
            int id = sqlite.findProductIdByNameStockPrice(name, stock, price);
            
            if (id != -1) {
                // Proceed with the update if the ID is found
                String username = Login.loggedInUsername;
                sqlite.updateProduct(username, id, updatedName, updatedStock, updatedPrice);
                System.out.println("✅ Product updated successfully!");
                
                tableModel.setValueAt(updatedName, table.getSelectedRow(), 0); // Update product name
                tableModel.setValueAt(updatedStock, table.getSelectedRow(), 1); // Update product stock
                tableModel.setValueAt(updatedPrice, table.getSelectedRow(), 2); // Update product price
            } else {
                // Handle case when product ID is not found
                System.out.println("❌ No product found matching the selected data.");
            }
        }
    }

    }//GEN-LAST:event_editBtnActionPerformed

    private void deleteBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_deleteBtnActionPerformed
        if(table.getSelectedRow() >= 0){
        
        // Retrieve the visible data from the selected row (assumes name is in column 0, price in column 2, stock in column 1)
        String name = (String) tableModel.getValueAt(table.getSelectedRow(), 0);
        int stock = (int) tableModel.getValueAt(table.getSelectedRow(), 1);
        Float priceFloat = (Float) tableModel.getValueAt(table.getSelectedRow(), 2);
        double price = priceFloat.doubleValue();

        // Confirm the deletion with the user
        int result = JOptionPane.showConfirmDialog(null, 
                "Are you sure you want to delete " + name + "?", 
                "DELETE PRODUCT", JOptionPane.YES_NO_OPTION);

        if (result == JOptionPane.YES_OPTION) {
            // Now, find the id of the product based on name, stock, and price
            int id = sqlite.findProductIdByNameStockPrice(name, stock, price);
            
            if (id != -1) {
                // If product ID was found, proceed with deletion
                
                String username = Login.loggedInUsername;
                sqlite.deleteProduct(username, id);

                tableModel.removeRow(table.getSelectedRow());
            } else {
                // Handle the case where the product was not found
                System.out.println("❌ No product found matching the selected data.");
            }
        }
    
}
    }//GEN-LAST:event_deleteBtnActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addBtn;
    private javax.swing.JButton deleteBtn;
    private javax.swing.JButton editBtn;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JButton purchaseBtn;
    private javax.swing.JTable table;
    // End of variables declaration//GEN-END:variables
}
