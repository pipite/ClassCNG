object Main: TMain
  Left = 0
  Top = 0
  Caption = 'Test application sous un autre compte'
  ClientHeight = 1111
  ClientWidth = 412
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OnClose = FormClose
  TextHeight = 13
  object Label1: TLabel
    Left = 8
    Top = 88
    Width = 25
    Height = 13
    Caption = 'Login'
  end
  object Label2: TLabel
    Left = 8
    Top = 116
    Width = 35
    Height = 13
    Caption = 'Domain'
  end
  object Label4: TLabel
    Left = 8
    Top = 60
    Width = 52
    Height = 13
    Caption = 'Application'
  end
  object LabelWinCrypt: TLabel
    Left = 8
    Top = 428
    Width = 161
    Height = 13
    Caption = 'Cryptage AES + SHA + Password'
  end
  object LbRSAKey: TLabel
    Left = 8
    Top = 624
    Width = 61
    Height = 13
    Caption = 'LabelRsaKey'
  end
  object Label3: TLabel
    Left = 8
    Top = 208
    Width = 262
    Height = 24
    Caption = 'Crypt AES + SHA + Password'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -20
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object Label5: TLabel
    Left = 8
    Top = 500
    Width = 289
    Height = 24
    Caption = 'Crypt RSA PBKDF2 + AES + SHA'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -20
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object Label6: TLabel
    Left = 8
    Top = 796
    Width = 379
    Height = 24
    Caption = 'Crypt RSA PBKDF2 + AES + SHA Password'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -20
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object LbRSACrypt: TLabel
    Left = 8
    Top = 775
    Width = 158
    Height = 13
    Caption = 'Cryptage RSA Public/Private AES'
  end
  object Label7: TLabel
    Left = 8
    Top = 1079
    Width = 263
    Height = 13
    Caption = 'Cryptage RSA Public/Private + AES + SHA + Password'
  end
  object Label8: TLabel
    Left = 24
    Top = 166
    Width = 259
    Height = 34
    Caption = 'Cryptage Sym'#233'trique'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -28
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object Label9: TLabel
    Left = 24
    Top = 456
    Width = 286
    Height = 34
    Caption = 'Cryptage Assym'#233'trique'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -28
    Font.Name = 'Tahoma'
    Font.Style = []
    ParentFont = False
  end
  object LbRsaPwd: TLabel
    Left = 8
    Top = 900
    Width = 63
    Height = 13
    Caption = 'LabelRsaPwd'
  end
  object Edit1: TEdit
    Left = 80
    Top = 56
    Width = 324
    Height = 21
    TabOrder = 0
    Text = 'C:\Windows\System32\Notepad.exe'
  end
  object Button1: TButton
    Left = 8
    Top = 8
    Width = 396
    Height = 42
    Caption = 'Tester l'#39'application avec un autre compte'
    TabOrder = 1
    OnClick = Button1Click
  end
  object Edit2: TEdit
    Left = 80
    Top = 85
    Width = 324
    Height = 21
    TabOrder = 2
    Text = 'btr-adm'
  end
  object Edit3: TEdit
    Left = 80
    Top = 112
    Width = 324
    Height = 21
    TabOrder = 3
    Text = 'lab.local'
  end
  object EdPassword: TMaskEdit
    Left = 119
    Top = 139
    Width = 225
    Height = 21
    PasswordChar = '*'
    TabOrder = 4
    Text = ''
  end
  object CBVisible: TCheckBox
    Left = 350
    Top = 141
    Width = 54
    Height = 17
    Caption = 'Visible'
    TabOrder = 5
    OnClick = CBVisibleClick
  end
  object BtPassword: TButton
    Left = 8
    Top = 139
    Width = 66
    Height = 21
    Caption = 'Password'
    TabOrder = 6
    OnClick = BtPasswordClick
  end
  object BtWinCryptFile: TButton
    Left = 8
    Top = 397
    Width = 185
    Height = 25
    Caption = 'AES Pwd Crypt File'
    TabOrder = 7
    OnClick = BtWinCryptFileClick
  end
  object BtWinDecryptFile: TButton
    Left = 208
    Top = 397
    Width = 196
    Height = 25
    Caption = 'AES Pwd Decrypt File'
    TabOrder = 8
    OnClick = BtWinDecryptFileClick
  end
  object EdExemple: TEdit
    Left = 8
    Top = 269
    Width = 396
    Height = 21
    TabOrder = 9
    Text = 'Ceci est une chaine '#224' crypter en AES + SHA + Password'
  end
  object WinEncrypt: TButton
    Left = 8
    Top = 296
    Width = 185
    Height = 25
    Caption = 'AES Pwd Enccrypt String'
    TabOrder = 10
    OnClick = WinEncryptClick
  end
  object EdWinEncrypt: TEdit
    Left = 8
    Top = 327
    Width = 396
    Height = 21
    TabOrder = 11
  end
  object WinDecrypt: TButton
    Left = 208
    Top = 296
    Width = 196
    Height = 25
    Caption = 'AES Pwd Deccrypt String'
    TabOrder = 12
    OnClick = WinDecryptClick
  end
  object EdFilepath: TEdit
    Left = 8
    Top = 370
    Width = 396
    Height = 21
    TabOrder = 13
    Text = 'C:\Local\Dev\Git\ClassCNG\Proj\Test.png'
  end
  object BtCreateKey: TButton
    Left = 8
    Top = 562
    Width = 121
    Height = 56
    Caption = 'New RSA Key'
    TabOrder = 14
    OnClick = BtCreateKeyClick
  end
  object BtLoadPublicRsaKey: TButton
    Left = 144
    Top = 593
    Width = 129
    Height = 25
    Caption = 'Import Public RSA Key'
    TabOrder = 15
    OnClick = BtLoadPublicRsaKeyClick
  end
  object BtSaveRSAPrivateKey: TButton
    Left = 285
    Top = 562
    Width = 119
    Height = 25
    Caption = 'Export Private Key'
    TabOrder = 16
    OnClick = BtSaveRSAPrivateKeyClick
  end
  object BtExportRSAPublicKey: TButton
    Left = 285
    Top = 593
    Width = 119
    Height = 25
    Caption = 'Export Public Key'
    TabOrder = 17
    OnClick = BtExportRSAPublicKeyClick
  end
  object BtRSAPublicKeyEncrypt: TButton
    Left = 8
    Top = 643
    Width = 185
    Height = 25
    Caption = 'RSA PublicKey Encrypt'
    TabOrder = 18
    OnClick = BtRSAPublicKeyEncryptClick
  end
  object BtRSAPrivateKeyDecrypt: TButton
    Left = 208
    Top = 643
    Width = 196
    Height = 25
    Caption = 'RSA PrivateKey Decrypt'
    TabOrder = 19
    OnClick = BtRSAPrivateKeyDecryptClick
  end
  object BtRSAPublicKeyCryptFile: TButton
    Left = 8
    Top = 744
    Width = 185
    Height = 25
    Caption = 'RSA PublicKey Crypt File'
    TabOrder = 20
    OnClick = BtRSAPublicKeyCryptFileClick
  end
  object BtRSAPrivateKeyDeCryptFile: TButton
    Left = 208
    Top = 744
    Width = 196
    Height = 25
    Caption = 'RSA PrivateKey DeCrypt File'
    TabOrder = 21
    OnClick = BtRSAPrivateKeyDeCryptFileClick
  end
  object BtLoadPrivateRsaKey: TButton
    Left = 144
    Top = 562
    Width = 129
    Height = 25
    Caption = 'Import Private RSA Key'
    TabOrder = 22
    OnClick = BtLoadPrivateRsaKeyClick
  end
  object EdRSACrypt: TEdit
    Left = 8
    Top = 674
    Width = 396
    Height = 21
    TabOrder = 23
  end
  object EdRSAExemple: TEdit
    Left = 8
    Top = 535
    Width = 396
    Height = 21
    TabOrder = 24
    Text = 'Ceci est une chaine '#224' crypter en RSA Public/Private AES'
  end
  object EdRSAFile: TEdit
    Left = 8
    Top = 717
    Width = 396
    Height = 21
    TabOrder = 25
    Text = 'C:\Local\Dev\Git\ClassCNG\Proj\Test.png'
  end
  object Button2: TButton
    Left = 8
    Top = 947
    Width = 185
    Height = 25
    Caption = 'RSA PublicKey Encrypt'
    TabOrder = 26
    OnClick = Button2Click
  end
  object Button3: TButton
    Left = 208
    Top = 946
    Width = 196
    Height = 25
    Caption = 'RSA PrivateKey Decrypt'
    TabOrder = 27
    OnClick = Button3Click
  end
  object EdRSAPwd: TEdit
    Left = 8
    Top = 977
    Width = 396
    Height = 21
    TabOrder = 28
  end
  object Edit5: TEdit
    Left = 8
    Top = 1021
    Width = 396
    Height = 21
    TabOrder = 29
    Text = 'C:\Local\Dev\Git\ClassCNG\Proj\Test.png'
  end
  object Button4: TButton
    Left = 208
    Top = 1048
    Width = 196
    Height = 25
    Caption = 'RSA PrivateKey DeCrypt File'
    TabOrder = 30
    OnClick = Button4Click
  end
  object Button5: TButton
    Left = 8
    Top = 1048
    Width = 185
    Height = 25
    Caption = 'RSA PublicKey Crypt File'
    TabOrder = 32
    OnClick = Button5Click
  end
  object Edit6: TEdit
    Left = 8
    Top = 919
    Width = 396
    Height = 21
    TabOrder = 31
    Text = 
      'Ceci est une chaine '#224' crypter en RSA Public/Private + AES + SHA ' +
      '+ Password'
  end
  object NumberBox: TEdit
    Left = 80
    Top = 139
    Width = 33
    Height = 21
    TabOrder = 33
    Text = '18'
  end
  object Button6: TButton
    Left = 8
    Top = 238
    Width = 92
    Height = 25
    Caption = 'New AES Key'
    TabOrder = 34
    OnClick = Button6Click
  end
  object Button7: TButton
    Left = 214
    Top = 238
    Width = 92
    Height = 25
    Caption = 'Load Key'
    TabOrder = 35
    OnClick = Button7Click
  end
  object Button8: TButton
    Left = 312
    Top = 238
    Width = 92
    Height = 25
    Caption = 'Save Key'
    TabOrder = 36
    OnClick = Button8Click
  end
  object Button9: TButton
    Left = 107
    Top = 238
    Width = 92
    Height = 25
    Caption = 'Set Password'
    TabOrder = 37
    OnClick = Button9Click
  end
  object Button10: TButton
    Left = 8
    Top = 834
    Width = 121
    Height = 25
    Caption = 'New RSA Key'
    TabOrder = 38
    OnClick = Button10Click
  end
  object Button11: TButton
    Left = 144
    Top = 865
    Width = 129
    Height = 25
    Caption = 'Import Public RSA Key'
    TabOrder = 39
    OnClick = Button11Click
  end
  object Button12: TButton
    Left = 285
    Top = 834
    Width = 119
    Height = 25
    Caption = 'Export Private Key'
    TabOrder = 40
    OnClick = Button12Click
  end
  object Button13: TButton
    Left = 285
    Top = 865
    Width = 119
    Height = 25
    Caption = 'Export Public Key'
    TabOrder = 41
    OnClick = Button13Click
  end
  object Button14: TButton
    Left = 144
    Top = 834
    Width = 129
    Height = 25
    Caption = 'Import Private RSA Key'
    TabOrder = 42
    OnClick = Button14Click
  end
  object Button15: TButton
    Left = 8
    Top = 865
    Width = 121
    Height = 25
    Caption = 'Set Password'
    TabOrder = 43
    OnClick = Button15Click
  end
end
