/**

   © Copyright 2017 Edgar Aguiniga ©
   This file is part of LoginPwds.

   LoginPwds is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   LoginPwds is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with LoginPwds.  If not, see <http://www.gnu.org/licenses/>.

 **/
package net.ea.loginpwds;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.Marshaller;
import net.ea.loginpwds.Keychain;
import net.ea.loginpwds.*;
import net.ea.loginpwds.PasswordGenerator;
import javax.swing.JComponent;
import java.awt.CardLayout;
import java.awt.*;
import java.awt.print.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.event.TreeSelectionEvent;
import java.awt.event.*;
import java.awt.BorderLayout;
import java.awt.Color;
import java.util.List;
import java.awt.*;
import java.util.*;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.text.MessageFormat;

public class LoginPwdFrame  extends JFrame 
{
  private static final boolean DBG = true;

  //frame dimensions before setup
  private static final int SETUP_FRAME_WIDTH = 500;
  private static final int SETUP_FRAME_HEIGHT = 300;

  //frame dimensions after setup
  private static final int FRAME_WIDTH = 1000;
  private static final int FRAME_HEIGHT = 600;

  private static CardLayout mainCardLayout;
  private static CardLayout fldCardLayout;
  private static CardLayout btnCardLayout;
  private static JPanel fldsCardPanel;
  private static JPanel btnsCardPanel;

  // show user instructions, error messages etc
  private JLabel msgArea;  

  // holds a cards panel and
  // a JTextArea
  private JPanel mainPanel;
  private JPanel mainCardsPnl;
  private JPanel createKeychainPnl;
  private JPanel authPanel;
  private JSplitPane treeAcctPane;
  private JPanel acctPanel;
  private JPanel keyPanel;

  // colors used for UI
  private Color foreground = Color.white;
  private Color background = Color.black;

  private static String userName = "";
  private static String masterPass = "";

  //File related
  private static final String usrHomeDir = System.getProperty("user.home");
  private static final String FILENAME = "loginpwds1.xml";
  private static File file;

  //structures for holding/manipulating 
  //data
  private static Keychain keychain;
  private static KeychainOwner keychainOwner;
  private static CipherInfo cipherInfo;
  private static Keyring keyring;
  private static Key currentKey;
  private static Account currentAccount;
  private static JTree tree;
  private static DefaultMutableTreeNode root;
  private static DefaultMutableTreeNode curNode;
  private static DefaultTreeModel treeModel;
  private static JScrollPane tree_ScrollPane;

  // For encryption
  private static CryptAES cryptAES;
  private static MessageDigest md;
  private static final int GOOD_PWD_LENGTH = 7;
  private static PasswordGenerator pg;

  // Auth Panel UI components
  private static JTextField userTxtField;
  private static JPasswordField passwordField;

  //Key card components
  private static JTextField keyNameFld;
  private static JTextField keyURLFld;

  // Account card components
  private static JTextField acct_nameFld;
  private static JTextField login_idFld;
  private static JTextField passwordFld;
  private static JTextArea notesArea;
  private static JTextArea secret_notesArea;
  private static JTextArea secret_questionArea;
  private static JButton newAccountBtn;
  private static JButton editAcctBtn;
  private static JButton deleteBtn;
  private static JButton genPwdBtn;

  // Generate Password Components
  private static JSpinner upperSpin; 
  private static JSpinner lowerSpin;  
  private static JSpinner digitsSpin;
  private static JSpinner punctuationSpin;
  private static JSpinner upperAlphaNumSpin;
  private static JSpinner lowerAlphaNumSpin;
  private static JSpinner alphaNumSpin;
  private static JSpinner allSpin;
  private static JTextField genPwdFld;

  // ui fields for creating new user 
  private static JTextField newUsrTxtFld;
  private static JPasswordField curPwdFld;
  private static JPasswordField newPwdFld;
  private static JPasswordField newPwdFld2;
  private static JPasswordField chgPwdFld;
  private static JPasswordField chgPwdFld2;

  //Names for different JPanels
  private static final String NEWUSRP = "New User JPanel";
  private static final String LOGINP = "Login JPanel";
  private static final String TREEACCTP = "Split Pane, JTree and Account JPanel";
  private static final String CHGPWDP = "JPanel for changing MASTER Password";
  private static final String GENPWDP = "JPanel for generating good Passwords";
  private static JLabel pwdDateLbl;

  //Names for fldsCardPanels
  private static final String KEYP = "JPanle to add/edit/del Keys";
  private static final String ACCTP = "JPanel to add/edit/del Accounts";
  private static final String INFOP = "JPanel to show when no Key/Account selected";

  //Names for btnsCardPanels
  private static final String EDITINGBP = "JPanle to Save or Cancel additions/edits";
  private static final String DEFAULTBP = "JPanel to Edit or Quit";
  private static final String SAVECANCELBP = "JPanel to Save changes or Cancel";

  private static boolean allowEditing;
  private static enum SELECTION {KEY, ACCOUNT, NEWKEY, NEWACCOUNT}
  private static SELECTION choice;

  private static TimeoutListener tl;
  private static boolean isNewKeychain = true;

  /**
   * LoginPwdFrame Constructor
   * @param Boolean, hasKeychain: if this user has a keychain
   */
  public LoginPwdFrame(boolean hasKeychain)
  {
    try
    {
      md = MessageDigest.getInstance("SHA-512");
    pg = new PasswordGenerator();
  // by default do not go into edit mode
  // if a keychain exists
  allowEditing = !hasKeychain;
  mainCardLayout = new CardLayout();
  mainCardsPnl = new JPanel(mainCardLayout);

  createKeychainPnl = createKeychainPnl();
  authPanel = createAuthPanel();
  treeAcctPane = createTreeAcctSplitPane(keychain.getKeyring());
  JPanel chgPwdPnl = changeKeychainPasswordPnl() ;
  //treeAcctPane.setName("treeAcctPane");

  JPanel genPwdP = createGenPwdPnl();

  mainCardsPnl.add(createKeychainPnl, NEWUSRP);
  mainCardsPnl.add(authPanel, LOGINP);
  mainCardsPnl.add(treeAcctPane, TREEACCTP);
  mainCardsPnl.add(chgPwdPnl , CHGPWDP);
  mainCardsPnl.add(genPwdP, GENPWDP);
  mainPanel = new JPanel(new BorderLayout());

  msgArea = new JLabel("Using " + file.getName() +" Please Authenticate",SwingConstants.CENTER);

  mainPanel.add(BorderLayout.NORTH, msgArea);
  mainPanel.add(BorderLayout.CENTER, mainCardsPnl);
  add(mainPanel);

  pack();
  setSize(SETUP_FRAME_WIDTH, SETUP_FRAME_HEIGHT);
  //center JFrame on screen
  //setLocationRelativeTo(null);  
  setLocationByPlatform(true);
  setVisible(true);

  Action act = new AbstractAction()
  {
    public void actionPerformed(ActionEvent e)
    {
      JFrame frame = (JFrame)e.getSource();
      System.out.println("timedout");
      secureQuit();

    }
  };

  tl = new TimeoutListener(this, act, 6);

  tl.start();

  if(hasKeychain)
  {
    isNewKeychain = false;
    mainCardLayout.show(mainCardsPnl, LOGINP);
    mainCardsPnl.revalidate();
  }
  }
  catch(NoSuchAlgorithmException nsae){}
  catch(Exception e){}
  }

  public static void main(String[] args) 
  {
    file = new File(usrHomeDir + File.separator + FILENAME);

    if(keychainExists(file))
    {
      keychain = unMarshallXML(file);
      keyring = keychain.getKeyring();

      LoginPwdFrame lpf  = new LoginPwdFrame(true);

      lpf.setVisible(true);
  }
  else
  {
    keychain = new Keychain();
    keychainOwner = new KeychainOwner();
    cipherInfo = new CipherInfo();
    keyring = new Keyring();
    keychain.setKeychainOwner(keychainOwner);
    keychain.setKeyring(keyring);

    LoginPwdFrame lpf  = new LoginPwdFrame(false);
    lpf.setVisible(true);
    choice = SELECTION.NEWKEY;
  }
  isKeyringEmpty();
  }

  public static boolean keychainExists(File keychainFile)
  {
    boolean hasKeychain = false;
    try
    {
      if(keychainFile.exists() && !keychainFile.isDirectory()) 
      { 
        hasKeychain = true;
        //unMarshallXML(file);
      }
  }
  catch(Exception e)
  {
    e.printStackTrace();
  }
  finally
  {
    return hasKeychain;
  }
  }

  private JPanel createAuthPanel() 
  {
    //JPanel to hold lables/textfields
    //JPanel txtPanel = new JPanel(new GridLayout(2,2));
    JPanel usrPanel = new JPanel(new GridLayout(1,2));
    JLabel userLabel = new JLabel("Username: ", SwingConstants.RIGHT);
    userTxtField = new JTextField();
    usrPanel.add(userLabel);
    usrPanel.add(userTxtField);

    JPanel pwdPanel = new JPanel(new GridLayout(1,2));
    JLabel pwdLabel = new JLabel("Password: ", SwingConstants.RIGHT);
    passwordField = new JPasswordField();
    // maybe
    //passwordField.setEchoChar(' ');
    pwdPanel.add(pwdLabel);
    pwdPanel.add(passwordField);

    //JPanel to hold buttons
    JPanel buttonPanel = new JPanel(new GridLayout(1,2));
    buttonPanel.setBorder(BorderFactory.createLineBorder(foreground));
    JButton loginButton = new JButton("Login");
    ActionListener loginListener = new LoginListener();
    loginButton.addActionListener(loginListener);
    JButton cancelButton = new JButton("Cancel");
    ActionListener cancelListener = new QuitListener();
    cancelButton.addActionListener(cancelListener);
    buttonPanel.add(loginButton);
    buttonPanel.add(cancelButton);

    //panel to hold the other panels
    JPanel topPanel = new JPanel(new GridLayout(3,1));
    topPanel.add(usrPanel);
    topPanel.add(pwdPanel);
    topPanel.add(buttonPanel);
    topPanel.setBorder(BorderFactory.createLineBorder(Color.BLUE));
    //topPanel.setName("LoginPanel");
    return topPanel;
  }//close createComponents methods

  /**
   * JSplitPane which has a JTree on Left, 
   * adn a CardsPanel on right. This is hte main 
   * interface, Keys/Accounts can be viewed/created
   * edited and deleted from here.
   * @param keyring, the Keyring Object
   * to view/manipula
   * @return JSplitPane
   */
  private JSplitPane createTreeAcctSplitPane(Keyring keyring) 
  {
    //Provide minimum sizes for the two components in the split pane
    Dimension minimumSize = new Dimension(500, 300);

    jtreeCreate(keyring);
    tree_ScrollPane = new JScrollPane(tree);
    tree_ScrollPane.setBorder(BorderFactory.createLineBorder(Color.GREEN,5));
    tree_ScrollPane.setPreferredSize(new Dimension(475,290));
    //tree_ScrollPane.setMinimumSize(minimumSize);

    JPanel acctPanel = createAccountPnl();
    acctPanel.setMinimumSize(minimumSize);
    JPanel keyPanel = createKeyPnl();
    keyPanel.setMinimumSize(minimumSize);

    //TODO add general info tips etc
    JPanel infoPanel = new JPanel();

    //-> 'cards' to add/edit Key's/Accounts
    fldCardLayout = new CardLayout();
    fldsCardPanel = new JPanel(fldCardLayout);
    fldsCardPanel.add(keyPanel, KEYP);
    fldsCardPanel.add(acctPanel, ACCTP);
    fldsCardPanel.add(infoPanel, INFOP);
    btnsCardPanel = createButtonsPnl();
    JPanel fldsBtnsPnl = new JPanel(new BorderLayout());
    fldsBtnsPnl.add(BorderLayout.CENTER, fldsCardPanel);
    fldsBtnsPnl.add(BorderLayout.SOUTH, btnsCardPanel);

    JSplitPane taPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
        tree_ScrollPane, fldsBtnsPnl);
    taPane.setDividerLocation(500);
    taPane.setOneTouchExpandable(true);

    //taPane.setName("TreeAcctPane");
    return taPane;
  }

  /**
   * JPanel with fields/buttons to add/edit/delete Accounts
   */
  private JPanel createAccountPnl() 
  {
    //JPanel acctPanel = new JPanel(new GridLayout(3,1));
    JPanel acctPanel = new JPanel(new BorderLayout() );

    JPanel acctPanel_1 = new JPanel(new GridLayout(8,1));
    JLabel acct_nameLbl = new JLabel("Account Name", SwingConstants.LEFT);
    acct_nameFld = new JTextField();
    acct_nameFld.getDocument().addDocumentListener(new JTextFieldChangeListener());
    acctPanel_1.add(acct_nameLbl);
    acctPanel_1.add(acct_nameFld);

    JLabel login_idLbl = new JLabel("Login ID:", SwingConstants.LEFT);
    login_idFld = new JTextField();
    login_idFld.getDocument().addDocumentListener(new JTextFieldChangeListener());
    acctPanel_1.add(login_idLbl);
    acctPanel_1.add(login_idFld);

    pwdDateLbl = new JLabel();
    JPanel pwdFldP = new JPanel(new GridLayout(1,2));
    JLabel passwordLbl = new JLabel("Password", SwingConstants.LEFT);
    passwordFld = new JTextField();
    passwordFld.getDocument().addDocumentListener(new JTextFieldChangeListener());
    //Button to generate good password
    genPwdBtn = new JButton("Password Help");
    genPwdBtn.setEnabled(false);
    genPwdBtn.setVisible(false);
    ActionListener genPwdL = new PwdHelpListener();
    genPwdBtn.addActionListener(genPwdL);
    pwdFldP.add(passwordLbl);
    pwdFldP.add(genPwdBtn);

    JLabel notesLbl = new JLabel("Notes:", SwingConstants.CENTER);
    acctPanel_1.add(pwdDateLbl);
    acctPanel_1.add(pwdFldP);
    acctPanel_1.add(passwordFld);
    acctPanel_1.add(notesLbl);

    JPanel acctPanel_2 = new JPanel(new BorderLayout());
    //JLabel notesLbl = new JLabel("Notes:", SwingConstants.CENTER);
    //notesArea = new JTextArea(rows, columns);
    notesArea = new JTextArea();
    notesArea.getDocument().addDocumentListener(new JTextFieldChangeListener());
    JScrollPane notesSP = new JScrollPane(notesArea);
    JPanel notesP = new JPanel();
    //notesP.add(notesSP);
    acctPanel_2.add(notesSP);

    acctPanel.add(BorderLayout.NORTH, acctPanel_1);
    acctPanel.add(BorderLayout.CENTER, acctPanel_2);

    acctPanel.setBorder(BorderFactory.createLineBorder(Color.RED,5));
    setAcctTxtEditable(false);
    return acctPanel;
  }

  /**
   * JPanel with fields/buttons to add/edit/delete Keys 
   */
  private JPanel createKeyPnl() 
  {
    JPanel keyFldsPanel = new JPanel(new GridLayout(2,2));
    JLabel keyNameLbl = new JLabel("Name of website or company:", SwingConstants.RIGHT);
    keyNameFld = new JTextField();
    keyNameFld.getDocument().addDocumentListener(new JTextFieldChangeListener());

    JLabel keyURLLbl =
      new JLabel("Url of website/company :", SwingConstants.RIGHT);
    keyURLFld = new JTextField();
    keyURLFld.getDocument().addDocumentListener(new JTextFieldChangeListener());

    keyFldsPanel.add(keyNameLbl);
    keyFldsPanel.add(keyNameFld);
    keyFldsPanel.add(keyURLLbl);
    keyFldsPanel.add(keyURLFld);

    JPanel keyPanel = new JPanel();
    keyPanel.add(keyFldsPanel);

    //keyFldsPanel.setPreferredSize(new Dimension(300,200));
    keyPanel.setBorder(BorderFactory.createLineBorder(Color.BLUE,10));
    return keyPanel;
  }

  /**
   * JPanel with fields/buttons to create a new Keychain 
   */
  private JPanel createKeychainPnl() 
  {
    JPanel createKeychainPnl = new JPanel(new GridLayout(5,2));

    JLabel newUsrLbl = new JLabel("Enter desired Username", SwingConstants.RIGHT);
    newUsrTxtFld = new JTextField();
    JLabel newPwdLble = new JLabel("Enter MASTER password", SwingConstants.RIGHT);
    newPwdFld = new JPasswordField();
    JLabel newPwdLble2 = new JLabel("Confirm MASTER password", SwingConstants.RIGHT);
    newPwdFld2 = new JPasswordField();

    createKeychainPnl.add(newUsrLbl);
    createKeychainPnl.add(newUsrTxtFld);

    createKeychainPnl.add(newPwdLble);
    createKeychainPnl.add(newPwdFld);

    createKeychainPnl.add(newPwdLble2);
    createKeychainPnl.add(newPwdFld2);

    JButton createBtn = new JButton("CREATE");
    ActionListener createListener = new CreateNewKeychainListener();
    createBtn.addActionListener(createListener);

    JButton cancelBtn = new JButton("Cancel");
    ActionListener cancelListener = new QuitListener();
    cancelBtn.addActionListener(cancelListener);

    createKeychainPnl.add(createBtn);
    createKeychainPnl.add(cancelBtn);

    //createKeychainPnl.setName("NewKeychainPanel");
    return createKeychainPnl;
  }

  /**
   * JPanel with fields/buttons to change Keychain password 
   */
  private JPanel changeKeychainPasswordPnl() 
  {
    JPanel changePwdPnl = new JPanel(new GridLayout(5,2));

    JLabel curPwdLbl = new JLabel("Enter Current Password: ", SwingConstants.RIGHT);
    curPwdFld = new JPasswordField();
    JLabel newPwdLble = new JLabel("Enter NEW MASTER password", SwingConstants.RIGHT);
    chgPwdFld = new JPasswordField();
    JLabel newPwdLble2 = new JLabel("Confirm NEW MASTER password", SwingConstants.RIGHT);
    chgPwdFld2 = new JPasswordField();

    changePwdPnl.add(curPwdLbl);
    changePwdPnl.add(curPwdFld);

    changePwdPnl.add(newPwdLble);
    changePwdPnl.add(chgPwdFld);

    changePwdPnl.add(newPwdLble2);
    changePwdPnl.add(chgPwdFld2);

    JButton changePwdBtn = new JButton("Change Password");
    ActionListener changePwdL = new ChangePwdListener();
    changePwdBtn.addActionListener(changePwdL);

    JButton cancelBtn = new JButton("Cancel");
    ActionListener cancelListener = new CancelListener();
    cancelBtn.addActionListener(cancelListener);

    changePwdPnl.add(changePwdBtn);
    changePwdPnl.add(cancelBtn);

    //changePwdPnl.setName("NewKeychainPanel");
    return changePwdPnl;
  }

  /**
   * JPanel for creating a good password
   */
  private JPanel createGenPwdPnl()
  {
    JPanel spinBtnP = new JPanel(new GridLayout(8,1));

    // JSpinners
    //  SpinnerNumberModel model =
    //  new SpinnerNumberModel(value, min, max, step);
    JPanel upperP = new JPanel(new GridLayout(1, 3));
    JLabel upperL =
      new JLabel("Uppercase Letters A-Z", SwingConstants.RIGHT);
    SpinnerNumberModel upperModel =
      new SpinnerNumberModel(0, 0, 100, 1);
    upperSpin = new JSpinner(upperModel);
    upperSpin.setEditor(new JSpinner.NumberEditor(upperSpin));
    JButton upperSpinBtn = new JButton("add");
    ActionListener upL = new GPupperListener();
    upperSpinBtn.addActionListener(upL);
    upperP.add(upperL);
    upperP.add(upperSpin);
    upperP.add(upperSpinBtn);
    spinBtnP.add(upperP);

    JPanel lowerP = new JPanel(new GridLayout(1, 3));
    JLabel lowerL =
      new JLabel("Lowercase Letters a-z", SwingConstants.RIGHT);
    SpinnerNumberModel lowerModel =
      new SpinnerNumberModel(0, 0, 100, 1);
    lowerSpin = new JSpinner(lowerModel);
    lowerSpin.setEditor(new JSpinner.NumberEditor(lowerSpin));
    JButton lowerSpinBtn = new JButton("add");
    ActionListener lowL = new GPlowerListener();
    lowerSpinBtn.addActionListener(lowL);
    lowerP.add(lowerL);
    lowerP.add(lowerSpin);
    lowerP.add(lowerSpinBtn);
    spinBtnP.add(lowerP);

    JPanel digitsP = new JPanel(new GridLayout(1, 3));
    JLabel digitL =
      new JLabel("Numbers 0-9", SwingConstants.RIGHT);
    SpinnerNumberModel digitsModel =
      new SpinnerNumberModel(0, 0, 100, 1);
    digitsSpin = new JSpinner(digitsModel);
    digitsSpin.setEditor(new JSpinner.NumberEditor(digitsSpin));
    JButton digitSpinBtn = new JButton("add");
    ActionListener dl = new GPdigitListener();
    digitSpinBtn.addActionListener(dl);
    digitsP.add(digitL);
    digitsP.add(digitsSpin);
    digitsP.add(digitSpinBtn);
    spinBtnP.add(digitsP);

    JPanel punctP = new JPanel(new GridLayout(1, 3));
    JLabel punctL =
      new JLabel("Punctuation .,;:'{}()_-+*#@%^&/'\\\"|!=", SwingConstants.RIGHT);
    SpinnerNumberModel punctuationModel =
      new SpinnerNumberModel(0, 0, 100, 1);
    punctuationSpin = new JSpinner(punctuationModel);
    punctuationSpin.setEditor(new JSpinner.NumberEditor(punctuationSpin));
    JButton punctSpinBtn = new JButton("add");
    ActionListener pl = new GPpunctListener();
    punctSpinBtn.addActionListener(pl);
    punctP.add(punctL);
    punctP.add(punctuationSpin);
    punctP.add(punctSpinBtn);
    spinBtnP.add(punctP);

    JPanel upperAlphaNumP = new JPanel(new GridLayout(1, 3));
    JLabel upperAlphaNumL =
      new JLabel("Uppercase letters and numbers A-Z 0-9", SwingConstants.RIGHT);
    SpinnerNumberModel upperAlphaNumModel =
      new SpinnerNumberModel(0, 0, 100, 1);
    upperAlphaNumSpin = new JSpinner(upperAlphaNumModel);
    upperAlphaNumSpin.setEditor(new JSpinner.NumberEditor(upperAlphaNumSpin));
    JButton upperAlphaNumSpinBtn = new JButton("add");
    ActionListener uanL = new GPalphaUpNListener();
    upperAlphaNumSpinBtn.addActionListener(uanL);
    upperAlphaNumP.add(upperAlphaNumL);
    upperAlphaNumP.add(upperAlphaNumSpin);
    upperAlphaNumP.add(upperAlphaNumSpinBtn);
    spinBtnP.add(upperAlphaNumP);

    JPanel lowerAlphaNumP = new JPanel(new GridLayout(1, 3));
    JLabel lowerAlphaNumL =
      new JLabel("Lowercase letters and numbers a-z 0-9", SwingConstants.RIGHT);
    SpinnerNumberModel lowerAlphaNumModel =
      new SpinnerNumberModel(0, 0, 100, 1);
    lowerAlphaNumSpin = new JSpinner(lowerAlphaNumModel);
    lowerAlphaNumSpin.setEditor(new JSpinner.NumberEditor(lowerAlphaNumSpin));
    JButton lowerAlphaNumSpinBtn = new JButton("add");
    ActionListener lanL = new GPalphaLowNListener();
    lowerAlphaNumSpinBtn.addActionListener(lanL);
    lowerAlphaNumP.add(lowerAlphaNumL);
    lowerAlphaNumP.add(lowerAlphaNumSpin);
    lowerAlphaNumP.add(lowerAlphaNumSpinBtn);
    spinBtnP.add(lowerAlphaNumP);

    JPanel alphaNumP = new JPanel(new GridLayout(1, 3));
    JLabel alphaNumL =
      new JLabel("Letters and numbers A-Z a-z 0-9", SwingConstants.RIGHT);
    SpinnerNumberModel alphaNumModel =
      new SpinnerNumberModel(0, 0, 100, 1);
    alphaNumSpin = new JSpinner(alphaNumModel);
    alphaNumSpin.setEditor(new JSpinner.NumberEditor(alphaNumSpin));
    JButton alphaNumSpinBtn = new JButton("add");
    ActionListener anL = new GPalphaNListener();
    alphaNumSpinBtn.addActionListener(anL);
    alphaNumP.add(alphaNumL);
    alphaNumP.add(alphaNumSpin);
    alphaNumP.add(alphaNumSpinBtn);
    spinBtnP.add(alphaNumP);

    JPanel allP = new JPanel(new GridLayout(1, 3));
    JLabel allL =
      new JLabel("Letters, Numbers and Punctuation", SwingConstants.RIGHT);
    SpinnerNumberModel allModel =
      new SpinnerNumberModel(100, 0, 100, 1);
    allSpin = new JSpinner(allModel);
    allSpin.setEditor(new JSpinner.NumberEditor(allSpin));
    JButton allSpinBtn = new JButton("add");
    ActionListener aL = new GPallListener();
    allSpinBtn.addActionListener(aL);
    allP.add(allL);
    allP.add(allSpin);
    allP.add(allSpinBtn);
    spinBtnP.add(allP);

    JPanel fldsBtnP = new JPanel(new GridLayout(3,1));

    JLabel genPwdL = new JLabel("Generated Password", SwingConstants.CENTER);
    fldsBtnP.add(genPwdL);
    genPwdFld = new JTextField();
    fldsBtnP.add(genPwdFld);

    JPanel gBtnP = new JPanel(new GridLayout(1,6));

    JButton undoBtn = new JButton("undo");
    ActionListener uL = new GPbackspaceListener();
    undoBtn.addActionListener(uL);
    gBtnP.add(undoBtn);

    JButton resetBtn = new JButton("reset");
    ActionListener rL = new GPresetListener();
    resetBtn.addActionListener(rL);
    gBtnP.add(resetBtn);

    JButton usePwdBtn = new JButton("Use this Password");
    ActionListener usepL = new GPuseListener();
    usePwdBtn.addActionListener(usepL);
    gBtnP.add(usePwdBtn);

    JButton cnclBtn = new JButton("Cancel");
    ActionListener cl = new CancelListener();
    cnclBtn.addActionListener(cl);
    gBtnP.add(cnclBtn);

    fldsBtnP.add(gBtnP);

    JPanel genPwdP = new JPanel(new BorderLayout());
    genPwdP.add(spinBtnP, BorderLayout.EAST);
    genPwdP.add(fldsBtnP, BorderLayout.SOUTH);


    return genPwdP;
  }

  /**
   * JPanel with a CardLayout to manage key/account  buttons
   */
  private JPanel createButtonsPnl() 
  {
    //defualt buttons
    JPanel defaultBtnPnl = new JPanel(new GridLayout(2,2));
    JButton editBtn = new JButton("Edit");
    ActionListener editL = new EditListener();
    editBtn.addActionListener(editL);

    JButton quitBtn = new JButton("Save and Quit");
    ActionListener quitL = new QuitListener();
    quitBtn.addActionListener(quitL);

    JButton chgPwdBtn = new JButton("Change MASTER Password");
    ActionListener goChgPwdBtn = new GoChangePwdListener();
    chgPwdBtn.addActionListener(goChgPwdBtn);

    JButton printBtn = new JButton("PRINT KEYCHAIN");
    ActionListener pl = new PrintListener();
    printBtn.addActionListener(pl);

    defaultBtnPnl.add(editBtn);
    defaultBtnPnl.add(printBtn);
    defaultBtnPnl.add(chgPwdBtn);
    defaultBtnPnl.add(editBtn);
    defaultBtnPnl.add(quitBtn);

    // Buttons used in edit view
    JButton newKeyBtn = new JButton("Add Key");
    ActionListener nkl = new NewKeyListener();
    newKeyBtn.addActionListener(nkl);

    newAccountBtn = new JButton("Add Account");
    ActionListener addAcctL = new NewAccountListener();
    newAccountBtn.addActionListener(addAcctL);

    deleteBtn = new JButton("DELETE");
    ActionListener deleteL = new DeleteListener();
    deleteBtn.addActionListener(deleteL);

    JButton cancelKeyBtn = new JButton("Cancel");
    ActionListener cancelKL = new CancelListener();
    cancelKeyBtn.addActionListener(cancelKL);

    JPanel editBtnPnl = new JPanel(new GridLayout(2,4));

    editBtnPnl.add(newKeyBtn);
    editBtnPnl.add(newAccountBtn);
    editBtnPnl.add(deleteBtn);
    editBtnPnl.add(cancelKeyBtn);

    // Buttons used in edit view for Keys/Accounts
    JPanel saveCancelBtnPnl = new JPanel(new GridLayout(1,2)); 

    JButton saveBtn = new JButton("Save");
    ActionListener saveL = new SaveListener();
    saveBtn.addActionListener(saveL);

    JButton cancelBtn = new JButton("Cancel");
    ActionListener cancelL = new CancelListener();
    cancelBtn.addActionListener(cancelL);

    saveCancelBtnPnl.add(saveBtn);
    saveCancelBtnPnl.add(cancelBtn);


    //-> cards for buttons
    btnCardLayout = new CardLayout();
    btnsCardPanel = new JPanel(btnCardLayout);
    btnsCardPanel.add(editBtnPnl, EDITINGBP);
    btnsCardPanel.add(saveCancelBtnPnl, SAVECANCELBP);
    btnsCardPanel.add(defaultBtnPnl, DEFAULTBP);
    //btnsCardPanel.add(defaultBtnPnl, SAVECANCELBP);

    btnsCardPanel.setPreferredSize(new Dimension(50,100));
    return btnsCardPanel;
  }

  /**
   * Method to see if a password is unique
   * within this keychain
   * @param pwd, the String to check
   * @return boolean, wether password is unique in this keychain
   */
  public static boolean isPasswordUnique(String pwd)
  {
    boolean isUniq = true;
    for(Key k : keyring.getKey())
    {
      for(Account a : k.getAccount())
      {
        if(a.getPassword().equals(pwd))
        {
          isUniq = false;
          return isUniq;
  }
      }

  }
  return isUniq;
  }

  /**
   * Method to check login/Password
   * for common bad practices
   * @param String loginID
   * @param String pwd
   * @return boolean
   */
  public boolean idPwdTest(String loginId, String pwd) 
  {
    boolean testFailed = false;
    String msg = "This password has the following issue(s): \n "; 
    if(pwd.length() < GOOD_PWD_LENGTH)
    {
      testFailed = true;
      msg +=
        "This password is too short, passwords should contain at least" + GOOD_PWD_LENGTH + " characters";
    }
    if((loginId.equals(pwd)))
    {
      testFailed = true;
      msg +=
        "\nlogins and Passwords should NOT be the SAME!";
    }
    if(!isPasswordUnique(pwd))
    {
      testFailed = true;
      msg +=
        "\nThis password has already been used for something else,"; 
    }
    if(usesWords(pwd))
    {
      testFailed = true;
      msg +=
        "\nThis password contains common english words or names, this should be avoided !";
    }
    if(usesBadPwds(pwd))
    {
      testFailed = true;
      msg +=
        "\nThis password uses or contains a well known and commonly used password!";
    }
    if(testFailed)
    {
      msg += "\n\n Use it anyway? ";

      Object[] options = { "YES", "NO" };
      int answer = 
        JOptionPane.showOptionDialog(
            null, msg, "WARNING: ",
            JOptionPane.DEFAULT_OPTION,
            JOptionPane.WARNING_MESSAGE,
            null, options, options[1]);
      if(answer == 0)//YES
      {
        // user doesn't care 
        testFailed = false;
      }
    }
    return !testFailed;
  }

  /**
   * Method to see if a password contains
   * english words or names 
   * @param pwd, the String to check
   * @return boolean, if password uses words/names 
   */
  public boolean usesWords(String pwd)
  {
    boolean usesWords = false;
    String pwdL = pwd.toLowerCase();
    BufferedReader in = null;

    try
    {
      InputStream ins = getClass().getResourceAsStream("/allwords.dat"); 
      in = new BufferedReader(new InputStreamReader(ins));

      String line = null;
      while((line = in.readLine()) != null)
      {
        String lineL = line.toLowerCase();
        if((lineL.contains(pwdL)) || (lineL.equals(pwdL)))
        {
          usesWords = true;
          break;
        }
      }
      in.close();  //very important to close streams
    }
    catch(Exception e){e.printStackTrace();}
    return usesWords;
  }

  /**
   * Method to see if a password contains
   * commonly used passwords  
   * @param pwd, the String to check
   * @return boolean, wether password uses common passwords 
   */
  public boolean usesBadPwds(String pwd)
  {
    boolean usesBadPwds = false;
    String pwdL = pwd.toLowerCase();
    BufferedReader in = null;

    try
    {

      InputStream ins = getClass().getResourceAsStream("/badpwds.dat"); 
      in = new BufferedReader(new InputStreamReader(ins));

      String line = null;
      while((line = in.readLine()) != null)
      {
        String lineL = line.toLowerCase();
        if((lineL.contains(pwdL)) || (lineL.equals(pwdL)))
        {
          usesBadPwds = true;
          break;
        }
      }
      in.close();  //very important to close streams
    }
    catch(Exception e){}
    return usesBadPwds;
  }


  /**
   * Method to lock/unlock Key fields
   * @param lock, Boolean wether fields 
   * should be locked
   */
  private void setKeyTxtEditable(boolean lock)
  { 
    keyNameFld.setEditable(lock);
    keyURLFld.setEditable(lock);
  }

  /**
   * Method to clear Key fields
   */
  private void clearKeyTxtFlds()
  {
    keyNameFld.setText("");
    keyURLFld.setText("");
  }

  /**
   * Method to lock/unlock fields
   * @param lock, Boolean wether fields 
   * should be locked
   */
  private void setAcctTxtEditable(boolean lock)
  {
    genPwdBtn.setEnabled(lock);
    genPwdBtn.setVisible(lock);
    acct_nameFld.setEditable(lock);
    login_idFld.setEditable(lock);
    passwordFld.setEditable(lock);
    notesArea.setEditable(lock);
  }

  /**
   * Method to clear fields
   */
  private void clearAcctTxtFlds()
  {
    acct_nameFld.setText("");
    login_idFld.setText("");
    passwordFld.setText("");
    notesArea.setText("");
  }

  /**
   * Method to check if Keychain is empty
   * and enable/show
   * Add Account and Delete Buttons, if 
   * there are no keys, then should'n be
   * able to delete or add accounts 
   */
  private static void isKeyringEmpty()
  {
    boolean hasKey = true;
    if((keyring.getKey() == null) || (keyring.getKey().size() == 0))
    {
      hasKey = false;
    }
    newAccountBtn.setVisible(hasKey);
    newAccountBtn.setEnabled(hasKey);
    deleteBtn.setVisible(hasKey);
    deleteBtn.setEnabled(hasKey);
  }

  /**
   * Method to change UI Colors
   *@param JComponent to alter
   */
  private void setColors(JComponent jComponent)
  {
    jComponent.setBackground(background);
    jComponent.setForeground(foreground);
  }

  /**
   * Method to unmarshall a File 
   * into a 'Keychain'
   * @param keychainFile, a File
   * @return Keychain, the resulting keychain
   */
  private static Keychain unMarshallXML(File keychainFile)
  { 
    Keychain keychain = null;
    try
    {
      JAXBContext jaxbContext = JAXBContext.newInstance("net.ea.loginpwds");

      Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
      keychain = (Keychain)
        jaxbUnmarshaller.unmarshal(keychainFile); 
      //keychain = (Keychain)root.getValue();

      keychainOwner = keychain.getKeychainOwner();
    }
    catch (JAXBException e)
    {
      e.printStackTrace();
    }
    return keychain;
  }

  /**
   * Method to marshall a Keychain Object into 
   * the corresponding XML, this method writes
   * the xml to disk
   * @param kcXML, a Keychain Object
   */
  private static void marshalXMLtoFile(Keychain kcXML)
  {
    try 
    {            
      encryptSecrets(keyring.getKey());
      JAXBContext jaxbCtx = JAXBContext.newInstance("net.ea.loginpwds");
      Marshaller marshaller = jaxbCtx.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8"); 
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
      //marshaller.marshal(kcXML, System.out);

      OutputStream outStream = new FileOutputStream(usrHomeDir + File.separator + FILENAME);
      marshaller.marshal( kcXML, outStream );
    } 
    catch (JAXBException e)
    {
      e.printStackTrace();
    }
    catch (FileNotFoundException e)
    {
      e.printStackTrace();
    }
  }

  /**
   * Method to marshall a Keychain Object into 
   * the corresponding XML, this method places it 
   *  into a ByteArrayOutputStream
   * @param kcXML, a Keychain Object
   * @param baos, a ByteArrayOutputStream 
   */
  private static void marshalXMLtoStream(Keychain kcXML, ByteArrayOutputStream baos)
  {
    try 
    {            
      //encryptSecrets(keyring.getKey());
      JAXBContext jaxbCtx = JAXBContext.newInstance("net.ea.loginpwds");
      Marshaller marshaller = jaxbCtx.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_ENCODING, "UTF-8"); 
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
      //marshaller.marshal(kcXML, System.out);

      marshaller.marshal( kcXML, baos);
    } 
    catch (JAXBException e)
    {
      e.printStackTrace();
    }
  }

  /**Method which returns a sha512 hash of password and salt
   * encoded in Base64
   * @param String, passwordToHash the password
   * @param String, salt a salt to deter rainbow attacks
   * @return String, the hash in base64
   */
  public static String getSHA512Hash(String passwordToHash, String salt)
  {
    String hashedPassword = null;
    try 
    {
      md.update(salt.getBytes("UTF-8"));
      byte[] bytes = md.digest(passwordToHash.getBytes("UTF-8"));
      hashedPassword = new String(Base64.getEncoder().encode(bytes));
    } 
    catch (UnsupportedEncodingException e)
    {
      e.printStackTrace();
    }

    return hashedPassword;
  }

  /**
   * TODO
   */
  public static void encryptSecrets(List<Key> keys)
  {
    for(int i = 0; i<keys.size(); i++)
    {
      //cycle through all keys
      String cipherKeyName = cryptAES.crypt(keys.get(i).getKeyName());
      keys.get(i).setKeyName(cipherKeyName);

      String cipherKeyUrl = cryptAES.crypt(keys.get(i).getWebsite());
      keys.get(i).setWebsite(cipherKeyUrl);
      for(int j = 0; j<keys.get(i).getAccount().size();j++)
      {
        //cycle through all accounts in each key
        String cipherAcctName = cryptAES.crypt(keys.get(i).getAccount().get(j).getAccountName());
        keys.get(i).getAccount().get(j).setAccountName(cipherAcctName);

        String cipherLoginId = cryptAES.crypt(keys.get(i).getAccount().get(j).getLoginId());
        keys.get(i).getAccount().get(j).setLoginId(cipherLoginId);

        String cipherPwd = cryptAES.crypt(keys.get(i).getAccount().get(j).getPassword());
        keys.get(i).getAccount().get(j).setPassword(cipherPwd);

        String cipherPwdDate = cryptAES.crypt(keys.get(i).getAccount().get(j).getPasswordSetDate());
        keys.get(i).getAccount().get(j).setPasswordSetDate(cipherPwdDate);

        String cipherNote = cryptAES.crypt(keys.get(i).getAccount().get(j).getNotes());
        keys.get(i).getAccount().get(j).setNotes(cipherNote);

        //       String cipherSecA = cryptAES.crypt(sq.getSecretAnswer());
        //       sq.setSecretAnswer(cipherSecA);
        //
      }
    }
  }

  /**
   * TODO
   */
  public static void decryptSecrets(List<Key> keys)
  {
    for(int i = 0; i<keys.size(); i++)
    {
      //cycle through all keys
      String plainKeyName = cryptAES.decrypt(keys.get(i).getKeyName());
      keys.get(i).setKeyName(plainKeyName);

      String plainKeyUrl = cryptAES.decrypt(keys.get(i).getWebsite());
      keys.get(i).setWebsite(plainKeyUrl);

      for(int j = 0; j<keys.get(i).getAccount().size();j++)
      {
        //cycle through all accounts in each key
        String plainAcctName = cryptAES.decrypt(keys.get(i).getAccount().get(j).getAccountName());
        keys.get(i).getAccount().get(j).setAccountName(plainAcctName);

        String plainLoginId = cryptAES.decrypt(keys.get(i).getAccount().get(j).getLoginId());
        keys.get(i).getAccount().get(j).setLoginId(plainLoginId);

        String plainPwd = cryptAES.decrypt(keys.get(i).getAccount().get(j).getPassword());
        keys.get(i).getAccount().get(j).setPassword(plainPwd);

        String plainPwdDate = cryptAES.decrypt(keys.get(i).getAccount().get(j).getPasswordSetDate());
        keys.get(i).getAccount().get(j).setPasswordSetDate(plainPwdDate);

        String plainPubNote = cryptAES.decrypt(keys.get(i).getAccount().get(j).getNotes());
        keys.get(i).getAccount().get(j).setNotes(plainPubNote);

        //     for(int k = 0; k<acctList.get(j).getSecretQuestion().size(); k++)
        //     {
        //       String plainSecQ = cryptAES.decrypt(sq.getSecretQuestion());
        //       sq.setSecretQuestion(plainSecQ);

        //       String plainSecA = cryptAES.decrypt(sq.getSecretAnswer());
        //       sq.setSecretAnswer(plainSecA);
        //
        }
      }
    }

    /**
     * Method to create a JTree from a Keyring
     * @param keyring, the Keyring Object with the data
     * @return JTree, UI component for displaying/manipulating data
     */
    public void jtreeCreate(Keyring keyring)
    {
      // root of tree
      root = 
        new DefaultMutableTreeNode(keychain.toString());

      for (Key k : keyring.getKey())
      {
        // this adds every key to the root node
        DefaultMutableTreeNode curKey = new DefaultMutableTreeNode(k);
        root.add(curKey);

        // this adds every account to its Key
        for (Account acct : k.getAccount())
        {
          DefaultMutableTreeNode acct_node  = new DefaultMutableTreeNode(acct);
          curKey.add(acct_node);
        }
      }

      treeModel = new DefaultTreeModel(root);
      tree = new JTree(treeModel);
      tree.getSelectionModel().setSelectionMode(
          TreeSelectionModel.SINGLE_TREE_SELECTION);

      // hide tree root node
      tree.setRootVisible(false); 

      //Listen for when the selection changes.
      TreeListener tsl = new TreeListener();
      tree.addTreeSelectionListener(tsl);
    }

    /**
     * Method to remove Keys
     * from JTree
     * @param key, the Key to be removed 
     */
    public void jtreeRemoveKey(Keyring kr, Key key)
    {
      kr.getKey().remove(key);
      DefaultTreeModel model = (DefaultTreeModel)tree.getModel();
      DefaultMutableTreeNode root = (DefaultMutableTreeNode)model.getRoot();
      //root.remove(key);
      //model.reload(root);
      model.removeNodeFromParent(curNode);
      allowEditing = false;
      isKeyringEmpty();
    }

    /**
     * Method to add a new Key 
     */
    public void saveNewKey() 
    {
      String keyName = keyNameFld.getText();
      String keyUrl = keyURLFld.getText();
      //TODO should add a check to make sure key is not
      //a duplicate
      if((keyName.length() <= 0) || (keyUrl.length() <= 0))
      {
        msgArea.setText("Please enter both a name and website" );
        JOptionPane.showMessageDialog(null,
            "name and website are both required ",
            "Error: ",JOptionPane.ERROR_MESSAGE);
      }
      else
      {
        setKeyTxtEditable(false);
        Key newKey = new Key();
        newKey.setKeyName(keyName);
        newKey.setWebsite(keyUrl);
        keyring.getKey().add(newKey);
        DefaultMutableTreeNode newNode = new DefaultMutableTreeNode(newKey);
        curNode = newNode;
        currentKey = newKey;
        // root.add(curNode);
        treeModel.insertNodeInto(newNode, root,0);
        treeModel.reload(root);
        // enable Account buttons if 
        // necessary
        isKeyringEmpty();
        // after adding a key, should add
        // an Account
        allowEditing = false;
        createAcct();
      }
    }

    /**
     * Method to save changes to a Key 
     */
    public void saveEditedKey() 
    {
      String keyName = keyNameFld.getText();
      String keyUrl = keyURLFld.getText();
      if((keyName.length() <= 0) || (keyUrl.length() <= 0))
      {
        msgArea.setText("Please enter both a name and website" );
        JOptionPane.showMessageDialog(null,
            "name and website are both required ",
            "Error: ",JOptionPane.ERROR_MESSAGE);
      }
      else
      {
        currentKey.setKeyName(keyName);
        currentKey.setWebsite(keyUrl);
        allowEditing = false;
        setKeyTxtEditable(false);
        treeModel.nodeStructureChanged(root);
        treeModel.reload();
        btnCardLayout.show(btnsCardPanel, DEFAULTBP);
      }
    }

    /**
     * Method to delete a Key 
     */
    public void deleteKey() 
    {
      // Display confirmation prompt
      Object[] options = { "YES", "CANCEL" };
      int answer = JOptionPane.showOptionDialog(null,
          "Delete " + currentKey.toString() + " ?", "Warning",
          JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
          null, options, options[1]);
      //Yes
      if(answer == 0)
      {
        jtreeRemoveKey(keyring, currentKey);
      }
      //Cancel
      else if(answer == 1)
      {
      }
      btnCardLayout.show(btnsCardPanel, DEFAULTBP);
      treeModel.nodeStructureChanged(root);
      allowEditing = false;
    }

    public void createAcct()
    {
      allowEditing = true;
      choice = SELECTION.NEWACCOUNT;
      fldCardLayout.show(fldsCardPanel, ACCTP);
      btnCardLayout.show(btnsCardPanel, SAVECANCELBP);
      setAcctTxtEditable(true);
      clearAcctTxtFlds();
    }

    /**
     * Method to Check new Account 
     */
    public void submitAcct()
    { 
      String acctN = acct_nameFld.getText();
      String loginId = login_idFld.getText();
      String pwd = passwordFld.getText();
      String note = notesArea.getText();
      //String secQ = secret_questionArea.getText();
      if((acctN.length() <= 0) || (loginId.length() <= 0) || (pwd.length() <= 0))
      {
        msgArea.setText("Account Name, Login ID, and Password Fields are required");
        JOptionPane.showMessageDialog(null,
            "Account Name, Login ID, and Password Fields are required",
            "Error: ",JOptionPane.ERROR_MESSAGE);
      }
      else 
      {
        // check login/password for common bad practices
        if(idPwdTest(loginId, pwd))
        {
          switch(choice)
          {
            case NEWACCOUNT:
              saveNewAcct(acctN, loginId, pwd,note);
              break;

            case ACCOUNT:
              saveEditedAcct(acctN, loginId, pwd,note);
              break;

            default:
              System.out.println("case default : ?.");
              break;
          }

        }
      }
    }

    /** 
     * Methodto SAVE new Account
     */
    public void saveNewAcct(String acctN, String loginId, String pwd, String note)
    {
      Account newAcct = new Account();
      newAcct.setAccountName(acctN);
      newAcct.setLoginId(loginId);
      newAcct.setPassword(pwd);
      String timeStamp =
        new SimpleDateFormat(
            "MM-dd-yyyy HH:mm:ss").format(
              Calendar.getInstance().getTime());
      newAcct.setPasswordSetDate(timeStamp);
      newAcct.setNotes(note);
      //secret_questionArea.setText();
      currentKey.getAccount().add(newAcct);
      currentAccount = newAcct;
      DefaultMutableTreeNode newNode =
        new DefaultMutableTreeNode(newAcct);
      Object obj = curNode.getUserObject();
      if (obj instanceof Account)
      {
        DefaultMutableTreeNode parentNode =
          (DefaultMutableTreeNode) curNode.getParent();
        curNode = parentNode; 
      }
      treeModel.insertNodeInto(newNode, curNode,0);
      treeModel.reload(root);
      btnCardLayout.show(btnsCardPanel, DEFAULTBP);
      fldCardLayout.show(fldsCardPanel, INFOP);
      setAcctTxtEditable(false);
      allowEditing = false;
    }

    /**
     * Method to save edited Account 
     */
    public void saveEditedAcct(String acctN, String loginId, String pwd, String note)
    {
      currentAccount.setAccountName(acctN);
      currentAccount.setLoginId(loginId);
      currentAccount.setPassword(pwd);
      String timeStamp =
        new SimpleDateFormat("yyyyMMdd_HHmmss").format(Calendar.getInstance().getTime());
      currentAccount.setPasswordSetDate(timeStamp);
      currentAccount.setNotes(note);
      //secret_questionArea.setText();
      treeModel.nodeStructureChanged(root);
      treeModel.reload();
      allowEditing = false;
      setAcctTxtEditable(false);
      btnCardLayout.show(btnsCardPanel, DEFAULTBP);
    }

    /**
     * Method to delete an Account 
     */
    public void deleteAccount() 
    {
      Object[] options = { "YES", "CANCEL" };
      int answer = JOptionPane.showOptionDialog(null,
          "Delete " + currentAccount.toString() + " ?", "Warning",
          JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
          null, options, options[1]);
      //YES
      if(answer == 0)
      {
        currentKey.getAccount().remove(currentAccount);
        DefaultMutableTreeNode node = 
          (DefaultMutableTreeNode)
          tree.getSelectionPath().getLastPathComponent();
        Object obj = node.getUserObject();
        if (obj instanceof Key)
        {
          // node.add(new DefaultMutableTreeNode(acct));
          //model.reload(curNode);
        }
        else 
        {
          DefaultMutableTreeNode parentNode = 
            (DefaultMutableTreeNode)
            node.getParent();
          parentNode.remove(node);
          //model.reload(parentNode);
          treeModel.nodeStructureChanged(parentNode);
          treeModel.reload();
        }
      }
      //CANCEL
      if(answer == 1)
      {
      }
      btnCardLayout.show(btnsCardPanel, DEFAULTBP);
      allowEditing = false;
    }

    /**
     * Method to delete a Node from JTree
     */
    public void deleteNode() 
    {
      Object[] options = { "YES", "CANCEL" };
      int answer = JOptionPane.showOptionDialog(null,
          "Delete " + curNode.toString() + " ?", "Warning this action Cannot be undone!",
          JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE,
          null, options, options[1]);
      //YES
      if(answer == 0)
      {
        Object obj = curNode.getUserObject();
        DefaultMutableTreeNode parentNode;
        if (obj instanceof Key)
        {
          keyring.getKey().remove(currentKey);
          curNode = null;
        }
        else 
        {
          parentNode = (DefaultMutableTreeNode)
            curNode.getParent(); 
          treeModel.removeNodeFromParent(curNode);
          curNode = parentNode;

          currentKey.getAccount().remove(currentAccount);
        }
      }
      //CANCEL
      if(answer == 1)
      {}
      btnCardLayout.show(btnsCardPanel, DEFAULTBP);
      allowEditing = false;
    }

    public void secureQuit()
    {
      if(!isNewKeychain)
      {
        marshalXMLtoFile(keychain);
      }
      dispose();
      System.exit(0);
    }

    /**
     * Class which implements ActionListener interface, 
     * contains code for button which creates a new Keychain
     */
    public class CreateNewKeychainListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          userName = newUsrTxtFld.getText();
          String masterPwd = new String(newPwdFld.getPassword());
          String masterPwd2 = new String(newPwdFld2.getPassword());
          //fields empty
          if((userName.length() <= 0) || (masterPwd.length() <= 0) || (masterPwd2.length() <= 0))
          {
            msgArea.setText("Please enter Username and Passwords");
            JOptionPane.showMessageDialog(null,
                "Username/Password are both required ",
                "Error: ",JOptionPane.ERROR_MESSAGE);
          }
          //fields not empty
          else
          {
            // passwords don't match 
            if(!masterPwd.equals(masterPwd2)) 
            {
              msgArea.setText("Passwords don't match");
              JOptionPane.showMessageDialog(null,
                  "Password don't match",
                  "Whoops!. ",JOptionPane.ERROR_MESSAGE);

            }
            // success! Create new Keychain
            else if(masterPwd.equals(masterPwd2))
            {
              if(idPwdTest(userName, masterPwd))
              {
                keychainOwner.setKeychainUsername(userName);
                keychainOwner.setKeychainPassword(getSHA512Hash(masterPwd, userName));

                mainCardLayout.show(mainCardsPnl, TREEACCTP);
                setSize(FRAME_WIDTH, FRAME_HEIGHT);
                mainCardsPnl.revalidate();
                cryptAES = new CryptAES(masterPwd, userName);
                cipherInfo.setSecureHashAlgorithm(md.getAlgorithm());
                cipherInfo.setSalt(userName);
                cipherInfo.setEncryptionAlgorithmInfo(cryptAES.getAlgorithm());
                //keychain.setKeychainOwner(keychainOwner);
                keychain.setCipherInfo(cipherInfo);
                isNewKeychain = false;

                //setSize(FRAME_WIDTH, FRAME_HEIGHT);

                msgArea.setText("Add Keys");
              }
            }
          }
        }
        catch(Exception e)
        { 
        }
      }
    }

    /**
     * Class which implements ActionListener interface, 
     * contains code for Login button 
     */
    public class LoginListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          userName = userTxtField.getText();
          masterPass = new String(passwordField.getPassword());
          if((userName.length() <= 0) || (masterPass.length() <= 0))
          {
            msgArea.setText("Please enter Username and Password");
            JOptionPane.showMessageDialog(null,
                "Username/Password are both required ",
                "Error: ",JOptionPane.ERROR_MESSAGE);
          }
          else
          {
            KeychainOwner keychainOwner = keychain.getKeychainOwner();
            if((keychainOwner.getKeychainUsername().equals(userName))
                &&
                (getSHA512Hash(masterPass,userName)
                 .equals(keychainOwner.getKeychainPassword())))
            {
              cryptAES = new CryptAES(masterPass,userName);
              decryptSecrets(keyring.getKey());
              treeModel.nodeStructureChanged(root);
              treeModel.reload(root);

              mainCardLayout.show(mainCardsPnl, TREEACCTP);
              fldCardLayout.show(fldsCardPanel, INFOP);
              btnCardLayout.show(btnsCardPanel, DEFAULTBP);
              setSize(FRAME_WIDTH, FRAME_HEIGHT);
              msgArea.setText("Using " + file.getName() + " View or Edit Keys");
            }
            else
            {
              msgArea.setText("Authentication Failed: Username or Password Incorrect");
              JOptionPane.showMessageDialog(null,
                  "Authentication Failed: Username or Password Incorrect",
                  "Error: ",JOptionPane.ERROR_MESSAGE);

            }
          }
        }
        catch(Exception e)
        { 
        }
      }
    }

    class GoChangePwdListener implements ActionListener 
    {
      public void actionPerformed(ActionEvent event)
      {
        allowEditing = true;
        mainCardLayout.show(mainCardsPnl, CHGPWDP);
      }
    }

    /**
     * Class which implements ActionListener interface, 
     * contains code Change Password button 
     */
    public class ChangePwdListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          String curMasterPass = new String(curPwdFld.getPassword());
          String newMasterPass = new String(chgPwdFld.getPassword());
          String newMasterPass2 = new String(chgPwdFld2.getPassword());
          // field(s) empty
          if((curMasterPass.length() <= 0) ||
              (newMasterPass.length() <= 0) ||
              (newMasterPass2.length() <= 0))
          {
            msgArea.setText("Please enter current Password, as well as the new desired Password");
            JOptionPane.showMessageDialog(null,
                "Current Password and the desired new Password are required ",
                "Error: ",JOptionPane.ERROR_MESSAGE);
          }
          else
          {
            // passwords don't match
            if (!newMasterPass.equals(newMasterPass2))
            {
              msgArea.setText(
                  "Whoops! : Passwords don't match");
              JOptionPane.showMessageDialog(null,
                  "Whoops! : Password don't match",
                  "Error: ",JOptionPane.ERROR_MESSAGE);
            }
            else
            {
              if((getSHA512Hash(curMasterPass, userName)
                    .equals(keychainOwner.getKeychainPassword()))
                  &&
                  (newMasterPass.equals(newMasterPass2)))
              {
                if(idPwdTest(userName, newMasterPass))
                {
                  keychainOwner.setKeychainPassword(getSHA512Hash(newMasterPass, userName));
                  keychain.setKeychainOwner(keychainOwner);

                  cryptAES = new CryptAES(newMasterPass, userName);
                  marshalXMLtoFile(keychain);
                  decryptSecrets(keyring.getKey());
                  curPwdFld.setText("");
                  chgPwdFld.setText("");
                  chgPwdFld2.setText("");
                  allowEditing = false;
                  mainCardLayout.show(mainCardsPnl, TREEACCTP);
                  fldCardLayout.show(fldsCardPanel, INFOP);
                  btnCardLayout.show(btnsCardPanel, DEFAULTBP);
                  setSize(FRAME_WIDTH, FRAME_HEIGHT);
                  msgArea.setText("Using " + file.getName() + " View or Edit Keys");
                }
              }
              else
              {
                msgArea.setText("Authentication Failed: Username or Password Incorrect");
                JOptionPane.showMessageDialog(null,
                    "Authentication Failed: Username or Password Incorrect",
                    "Error: ",JOptionPane.ERROR_MESSAGE);
              }
            }
          }
        }
        catch(Exception e)
        { 
        }
      }
    }

    /**
     * Class which implements ActionListener interface, 
     * contains code Password Help button 
     */
    public class PwdHelpListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          mainCardLayout.show(mainCardsPnl, GENPWDP);
          setSize(FRAME_WIDTH, FRAME_HEIGHT);
          msgArea.setText("Using " + file.getName() + " Password Help");
        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPupperListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {

          upperSpin.commitEdit(); 
          int upperSpinI = (Integer) upperSpin.getValue();
          if(upperSpinI > 0)
          {
            pg.addCharsUpper(upperSpinI);
            genPwdFld.setText(pg.toString());
          }

        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPlowerListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {

          lowerSpin.commitEdit(); 
          int lowerSpinI = (Integer) lowerSpin.getValue();
          if(lowerSpinI > 0)
          {
            pg.addCharsLower(lowerSpinI);
            genPwdFld.setText(pg.toString());
          }
        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPdigitListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          digitsSpin.commitEdit(); 
          int digitsSpinI = (Integer) digitsSpin.getValue();
          if(digitsSpinI > 0)
          {
            pg.addCharsDigits(digitsSpinI);
            genPwdFld.setText(pg.toString());
          }

        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPpunctListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          punctuationSpin.commitEdit(); 
          int punctuationSpinI = (Integer) punctuationSpin.getValue();
          if(punctuationSpinI > 0)
          {
            pg.addCharsPunctuation(punctuationSpinI);
            genPwdFld.setText(pg.toString());
          }

        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPalphaUpNListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          upperAlphaNumSpin.commitEdit(); 
          int upperAlphaNumSpinI = (Integer) upperAlphaNumSpin.getValue();
          if(upperAlphaNumSpinI > 0)
          {
            pg.addCharsUpperAlphaNum(upperAlphaNumSpinI);
            genPwdFld.setText(pg.toString());
          }
        }
        catch(Exception e)
        { 
        }
      }
    }


    public class GPalphaLowNListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {

          lowerAlphaNumSpin.commitEdit(); 
          int lowerAlphaNumSpinI = (Integer) lowerAlphaNumSpin.getValue();
          if(lowerAlphaNumSpinI > 0)
          {
            pg.addCharsLowerAlphaNum(lowerAlphaNumSpinI);
            genPwdFld.setText(pg.toString());
          }
        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPalphaNListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          alphaNumSpin.commitEdit(); 
          int alphaNumSpinI = (Integer) alphaNumSpin.getValue();
          if(alphaNumSpinI > 0)
          {
            pg.addCharsAlphaNum(alphaNumSpinI);
            genPwdFld.setText(pg.toString());
          }
        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPallListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {

          allSpin.commitEdit(); 
          int allSpinI = (Integer) allSpin.getValue();
          if(allSpinI > 0)
          {
            pg.addCharsAll(allSpinI);
            genPwdFld.setText(pg.toString());
          }
        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPbackspaceListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          pg.removeLast();
          genPwdFld.setText(pg.toString());
        }
        catch(Exception e){}
      }
    }

    public class GPresetListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {

          pg.reset();
          genPwdFld.setText(pg.toString());
        }
        catch(Exception e)
        { 
        }
      }
    }

    public class GPuseListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        //passwordFld.setText(genPwdFld.getText());
        passwordFld.setText(pg.toString());
        pg.reset();
        genPwdFld.setText("");
        mainCardLayout.show(mainCardsPnl, TREEACCTP);
      }
    }


    /**
     * Class which implements TreeSelectionListener interface, 
     * contains code for handling interaction with a JTree
     */
    public class TreeListener implements TreeSelectionListener
    {
      public void valueChanged(TreeSelectionEvent e) 
      {
        curNode = (DefaultMutableTreeNode)
          tree.getLastSelectedPathComponent();

        //Nothing is selected.  
        if (curNode == null)
        {
          fldCardLayout.show(fldsCardPanel, INFOP);
          btnCardLayout.show(btnsCardPanel, DEFAULTBP);
          return;
        }

        Object curNodeInfo = curNode.getUserObject();

        //if (curNode.isLeaf())
        if (curNodeInfo instanceof Account)
        {
          choice = SELECTION.ACCOUNT;
          //flip fldsCardPanel to 'Account'
          fldCardLayout.show(fldsCardPanel, ACCTP);

          currentAccount = (Account) curNodeInfo;

          //make sure currentKey points to correct Key
          DefaultMutableTreeNode parentNode = 
            (DefaultMutableTreeNode)
            curNode.getParent();

          Object parentNodeObj = parentNode.getUserObject();
          currentKey = (Key)parentNodeObj;

          acct_nameFld.setText(currentAccount.getAccountName());
          login_idFld.setText(currentAccount.getLoginId());
          pwdDateLbl.setText("set on: " + currentAccount.getPasswordSetDate());
          passwordFld.setText(currentAccount.getPassword());
          notesArea.setText(currentAccount.getNotes());
          //secret_questionArea.setText();
          if(allowEditing)
          {
            btnCardLayout.show(btnsCardPanel, EDITINGBP);
            setAcctTxtEditable(true);
          }else
          {
            btnCardLayout.show(btnsCardPanel, DEFAULTBP);
            setAcctTxtEditable(false);
          }
        }
        else if (curNodeInfo instanceof Key)
        {
          choice = SELECTION.KEY;
          fldCardLayout.show(fldsCardPanel, KEYP);
          currentKey  = (Key) curNodeInfo;
          //currentAccount should not point at anything yet
          currentAccount = null;

          keyNameFld.setText(currentKey.getKeyName());
          keyURLFld.setText(currentKey.getWebsite());

          if(allowEditing)
          {
            btnCardLayout.show(btnsCardPanel, EDITINGBP);
            setKeyTxtEditable(true);
          }else
          {
            btnCardLayout.show(btnsCardPanel, DEFAULTBP);
            setKeyTxtEditable(false);
          }
        }
        else
        {
          System.out.println(curNodeInfo.getClass());
        }
      }
    }

    /**
     * Class which implements DocumentListener interface, 
     * contains code to detect changes in a JTextField
     */
    public class JTextFieldChangeListener implements DocumentListener
    {
      public void changedUpdate(DocumentEvent e)
      {
        btnCardLayout.show(btnsCardPanel, SAVECANCELBP);
      }
      public void insertUpdate(DocumentEvent e)
      {
        btnCardLayout.show(btnsCardPanel, SAVECANCELBP);
      }
      public void removeUpdate(DocumentEvent e)
      {
        btnCardLayout.show(btnsCardPanel, SAVECANCELBP);
      }
    }

    /**
     * Class which implements ActionListener interface, 
     * contains code to enable editing of  Keys/Accounts
     */
    public class EditListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          allowEditing = true;
          setKeyTxtEditable(true);
          setAcctTxtEditable(true);

          //fldCardLayout.show(fldsCardPanel, INFOP);
          btnCardLayout.show(btnsCardPanel, EDITINGBP);
        }
        catch(Exception e)
        { 
          //TODO
        }
      }
    }

    /**
     * Class which implements ActionListener interface, 
     * contains code for done button (exit edit mode)
     */
    public class DoneListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          allowEditing = false;
          setKeyTxtEditable(false);
          setAcctTxtEditable(false);
          fldCardLayout.show(fldsCardPanel, KEYP);
          btnCardLayout.show(btnsCardPanel, DEFAULTBP);
        }
        catch(Exception e)
        { 
          //TODO
        }//close catch
      }//close actionPerformed method
    }

    /**
     * Class which implements ActionListener interface, 
     * contains code for button which creates a new Key
     */
    public class NewKeyListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          clearKeyTxtFlds();
          setKeyTxtEditable(true);
          fldCardLayout.show(fldsCardPanel, KEYP);
          btnCardLayout.show(btnsCardPanel, SAVECANCELBP);
          choice = SELECTION.NEWKEY;
        }
        catch(Exception e)
        { 
          //TODO
        }//close catch
      }//close actionPerformed method
    }

    /**
     * Class which implements ActionListener interface, 
     * sets ui up to create an Acct for a Key 
     */
    public class NewAccountListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          createAcct();
        }//close try
        catch(Exception e)
        { 
        }
      }
    }

    /**
     * Class which implements ActionListener interface, 
     * saves changes, writes modified file to disk
     */
    public class SaveListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          switch (choice)
          {
            case KEY:
              saveEditedKey();
              break;

            case NEWKEY:
              saveNewKey();
              break;

            case ACCOUNT:
              submitAcct();
              break;

            case NEWACCOUNT:
              submitAcct();
              break;

            default:
              System.out.println("case default : ?.");
              break;
          }
        }
        catch(Exception e){}
      }
    }

    /**
     * Class which implements ActionListener interface, 
     * Deletes Keys/Accounts 
     */
    public class DeleteListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        try
        {
          allowEditing = false;
          setKeyTxtEditable(false);
          setAcctTxtEditable(false);

          switch (choice)
          {
            case KEY:
              deleteKey();
              break;

            case ACCOUNT:
              deleteAccount();
              break;

            default:
              System.out.println("case default : ?.");
              JOptionPane.showMessageDialog(null,
                  "Please select a Key or Account to Delete",
                  "Error: ",JOptionPane.ERROR_MESSAGE);
              break;
          }
        }
        catch(Exception e)
        { 
        }
      }
    }

    public class CancelListener implements ActionListener
    {
      public void actionPerformed(ActionEvent event)
      {
        //what to do on button click 
        allowEditing = false;
        setKeyTxtEditable(false);
        setAcctTxtEditable(false);
        mainCardLayout.show(mainCardsPnl, TREEACCTP);
        fldCardLayout.show(fldsCardPanel, INFOP);
        btnCardLayout.show(btnsCardPanel, DEFAULTBP);
        setSize(FRAME_WIDTH, FRAME_HEIGHT);
      }
    }

    class PrintListener implements ActionListener 
    {
      public void actionPerformed(ActionEvent event)
      {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        marshalXMLtoStream(keychain, bos);
        final byte[] byteStream = bos.toByteArray();
        String xml = new String(byteStream);
        JEditorPane editPane = new JEditorPane();
        editPane.setText(xml);
        try {
          MessageFormat fmt =
            new MessageFormat(" *** WARNING * PRIVATE * CONFIDENTIAL *** \n Page - {0}");


          boolean complete =
            editPane.print(fmt, fmt,true,null,null,true );
          if (complete)
          {
            /* show a success message  */
            JOptionPane.showMessageDialog(null,
                "Printing Finished, don't leave your secrets sitting in the printr tray... PUT THEM AWAY SECURELY",
                "! ATTENTION !",JOptionPane.ERROR_MESSAGE);
          } else
          {
            /*show a message indicating that printing was cancelled */
            JOptionPane.showMessageDialog(null,
                "Printing Canceled.",
                "! ATTENTION !",JOptionPane.ERROR_MESSAGE);
          }
        } catch (PrinterException pe)
        {
          /* Printing failed, report to the user */
          JOptionPane.showMessageDialog(null,
              "Printing Failed!, Check the printer, make sure it has adequate supplied and is in working order.",
              "! ATTENTION !",JOptionPane.ERROR_MESSAGE);
        }

      }
    }


    class QuitListener implements ActionListener 
    {
      public void actionPerformed(ActionEvent event)
      {
        secureQuit();
      }
    }

    class TimeoutListener implements ActionListener, AWTEventListener
    {
      //Event mask to capture all keystrokes/mouse events
      public final static long ALLEVENTS = AWTEvent.KEY_EVENT_MASK +
        AWTEvent.MOUSE_MOTION_EVENT_MASK + AWTEvent.MOUSE_EVENT_MASK;
      //what to listen to
      private Window window;
      //what to do on timeout 
      private Action action;
      //how long before timeout (minutes)
      private int timeout;
      //triggers action on timeout
      private javax.swing.Timer timer = new javax.swing.Timer(0, this);

      public TimeoutListener(Window window, Action action, int minutes)
      {
        this.window = window;
        this.action = action;
        this.timeout = minutes;
      }

      public void start()
      {
        timer.setInitialDelay(timeout*60000);
        timer.setRepeats(false);
        timer.start();
        Toolkit.getDefaultToolkit().addAWTEventListener(this, ALLEVENTS);
      }

      public void stop()
      {
        Toolkit.getDefaultToolkit().removeAWTEventListener(this);
        timer.stop();
      }

      /**
       * What the timer does when the timeout 
       * is reached
       */
      public void actionPerformed(ActionEvent e)
      {
        ActionEvent ae = new ActionEvent(window, ActionEvent.ACTION_PERFORMED, "");
        action.actionPerformed(ae);
      }

      public void eventDispatched(AWTEvent e)
      {
        if (timer.isRunning())
          timer.restart();
      }
    }

  }//close LoginPwdFrame class
