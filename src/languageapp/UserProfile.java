/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JPanel.java to edit this template
 */
package languageapp;

/**
 *
 * @author catal
 */
public class UserProfile extends javax.swing.JPanel {
    
    // Attributes
    String userName = null;     // the name of the user
    String userID = null;       // the id of the user
    String userEmail = null;    // the email of the user
    int completedRP = 0;        // the number of the completed roleplays
    int A1RP = 0;               // the number of A1 completed roleplays
    int A2RP = 0;               // the number of A2 completed roleplays
    int B1RP = 0;               // the number of B1 completed roleplays
    int B2RP = 0;               // the number of B2 completed roleplays
    int accessedVocab = 0;      // the number of times the user has accessed the vocabulary support offered
    
    // Methods
    private void setStrings() {
        // This method sets the values of the user attributes from sign in.
        this.userName = null;
        this.userID = null;
        this.userEmail = null;
        // Replace null with values from the DB
    }
    private void setIntegers() {
        // This method sets the values of the user attributes from sign in.
        // The below attributes must be refreshed every time the profile tab is accessed.
        this.completedRP = 0;
        this.A1RP = 0;
        this.A2RP = 0;
        this.B1RP = 0;
        this.B2RP = 0;
        this.accessedVocab = 0;
        // Replace 0s with values from the DB
    }
    
    /**
     * Creates new form User Profile
     */
    public UserProfile() {
        setStrings();
        setIntegers();
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel2 = new javax.swing.JPanel();
        jTextFieldName = new javax.swing.JTextField();
        jTextFieldID = new javax.swing.JTextField();
        jTextFieldEmail = new javax.swing.JTextField();
        jButtonAnalytics = new javax.swing.JButton();
        jButtonMenu = new javax.swing.JButton();
        jButtonActivity = new javax.swing.JButton();
        jButtonSettings = new javax.swing.JButton();

        setAlignmentX(0.0F);
        setAlignmentY(0.0F);
        setMaximumSize(new java.awt.Dimension(230, 667));
        setMinimumSize(new java.awt.Dimension(230, 667));
        setPreferredSize(new java.awt.Dimension(230, 667));

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 100, Short.MAX_VALUE)
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 100, Short.MAX_VALUE)
        );

        jTextFieldName.setBackground(new java.awt.Color(215, 229, 240));
        jTextFieldName.setFont(new java.awt.Font("Lucida Bright", 1, 12)); // NOI18N
        jTextFieldName.setText("name");

        jTextFieldID.setBackground(new java.awt.Color(215, 229, 240));
        jTextFieldID.setFont(new java.awt.Font("Lucida Bright", 0, 8)); // NOI18N
        jTextFieldID.setText("ID");

        jTextFieldEmail.setBackground(new java.awt.Color(215, 229, 240));
        jTextFieldEmail.setFont(new java.awt.Font("Lucida Bright", 0, 10)); // NOI18N
        jTextFieldEmail.setText("email");
        jTextFieldEmail.setToolTipText("");
        jTextFieldEmail.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jTextFieldEmailActionPerformed(evt);
            }
        });

        jButtonAnalytics.setBackground(new java.awt.Color(160, 178, 231));
        jButtonAnalytics.setFont(new java.awt.Font("Lucida Bright", 1, 13)); // NOI18N
        jButtonAnalytics.setForeground(new java.awt.Color(255, 255, 255));
        jButtonAnalytics.setText("Analytics");
        jButtonAnalytics.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonAnalyticsActionPerformed(evt);
            }
        });

        jButtonMenu.setBackground(new java.awt.Color(160, 178, 231));
        jButtonMenu.setFont(new java.awt.Font("Lucida Bright", 1, 13)); // NOI18N
        jButtonMenu.setForeground(new java.awt.Color(255, 255, 255));
        jButtonMenu.setText("Menu");
        jButtonMenu.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonMenuActionPerformed(evt);
            }
        });

        jButtonActivity.setBackground(new java.awt.Color(160, 178, 231));
        jButtonActivity.setFont(new java.awt.Font("Lucida Bright", 1, 13)); // NOI18N
        jButtonActivity.setForeground(new java.awt.Color(255, 255, 255));
        jButtonActivity.setText("Activity");
        jButtonActivity.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonActivityActionPerformed(evt);
            }
        });

        jButtonSettings.setBackground(new java.awt.Color(160, 178, 231));
        jButtonSettings.setFont(new java.awt.Font("Lucida Bright", 1, 13)); // NOI18N
        jButtonSettings.setForeground(new java.awt.Color(255, 255, 255));
        jButtonSettings.setText("Settings");
        jButtonSettings.setToolTipText("");
        jButtonSettings.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonSettingsActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(61, 61, 61)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jButtonMenu, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonSettings, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonActivity, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonAnalytics, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextFieldEmail, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextFieldID, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jTextFieldName, javax.swing.GroupLayout.PREFERRED_SIZE, 100, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(69, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jTextFieldName, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTextFieldID, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTextFieldEmail, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(114, 114, 114)
                .addComponent(jButtonMenu)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonAnalytics)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jButtonActivity)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 159, Short.MAX_VALUE)
                .addComponent(jButtonSettings)
                .addGap(79, 79, 79))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void jTextFieldEmailActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jTextFieldEmailActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_jTextFieldEmailActionPerformed

    
    // 
    private void jButtonMenuActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonMenuActionPerformed
        // TODO add your handling code here:
        // Closes the profile panel and redirects the user to the menu of the app
        setVisible(false);
    }//GEN-LAST:event_jButtonMenuActionPerformed

    private void jButtonAnalyticsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonAnalyticsActionPerformed
        // TODO add your handling code here:
        // Closes the profile panel and redirects the user to the analytics
        setVisible(false);
    }//GEN-LAST:event_jButtonAnalyticsActionPerformed

    private void jButtonActivityActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonActivityActionPerformed
        // TODO add your handling code here:
        // Closes the profile panel and redirects the user to the user activity
        ActivityHistory activity = new ActivityHistory();
        setVisible(false);
        
    }//GEN-LAST:event_jButtonActivityActionPerformed

    private void jButtonSettingsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonSettingsActionPerformed
        // TODO add your handling code here:
        // Closes the profile panel and redirects the user to the settings of the app
        setVisible(false);
    }//GEN-LAST:event_jButtonSettingsActionPerformed


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButtonActivity;
    private javax.swing.JButton jButtonAnalytics;
    private javax.swing.JButton jButtonMenu;
    private javax.swing.JButton jButtonSettings;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JTextField jTextFieldEmail;
    private javax.swing.JTextField jTextFieldID;
    private javax.swing.JTextField jTextFieldName;
    // End of variables declaration//GEN-END:variables
}

// TEST