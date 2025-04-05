object RSA_AES: TRSA_AES
  Left = 0
  Top = 0
  Caption = 'RSA-AES'
  ClientHeight = 942
  ClientWidth = 578
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  TextHeight = 15
  object Button4: TButton
    Left = 8
    Top = 22
    Width = 545
    Height = 25
    Caption = 'Initialiser le contexte cryptographique'
    TabOrder = 0
    OnClick = Button4Click
  end
  object Button6: TButton
    Left = 8
    Top = 67
    Width = 545
    Height = 25
    Caption = 'G'#233'n'#233'rer une cl'#233' RSA (asym'#233'trique)'
    TabOrder = 1
    OnClick = Button6Click
  end
  object Button7: TButton
    Left = 8
    Top = 117
    Width = 545
    Height = 25
    Caption = 'G'#233'n'#233'rer une cl'#233' AES (sym'#233'trique) manuellement'
    TabOrder = 2
    OnClick = Button7Click
  end
  object Button8: TButton
    Left = 8
    Top = 165
    Width = 545
    Height = 25
    Caption = 'Cr'#233'er un hash SHA-256 (base pour CryptDeriveKey)'
    TabOrder = 3
    OnClick = Button8Click
  end
  object Button9: TButton
    Left = 8
    Top = 208
    Width = 545
    Height = 25
    Caption = 'Alimenter le hash avec la cl'#233' AES brute'
    TabOrder = 4
    OnClick = Button9Click
  end
  object Button10: TButton
    Left = 8
    Top = 251
    Width = 545
    Height = 25
    Caption = 'D'#233'river la cl'#233' AES-256 depuis le hash'
    TabOrder = 5
    OnClick = Button10Click
  end
  object Button11: TButton
    Left = 8
    Top = 331
    Width = 545
    Height = 25
    Caption = 'Chiffrer un message avec AES'
    TabOrder = 6
    OnClick = Button11Click
  end
  object LOG: TMemo
    Left = 8
    Top = 487
    Width = 562
    Height = 447
    TabOrder = 7
  end
  object Edit1: TEdit
    Left = 8
    Top = 296
    Width = 545
    Height = 23
    TabOrder = 8
    Text = 'Ceci est le message a chiffrer avec la cl'#233' sym'#233'trique AES-256'
  end
  object Edit2: TEdit
    Left = 8
    Top = 362
    Width = 545
    Height = 23
    TabOrder = 9
  end
end
