object Form3: TForm3
  Left = 0
  Top = 0
  Caption = 'SFTP client demo'
  ClientHeight = 403
  ClientWidth = 708
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  OnCreate = FormCreate
  DesignSize = (
    708
    403)
  PixelsPerInch = 96
  TextHeight = 13
  object lblCurDir: TLabel
    Left = 8
    Top = 120
    Width = 6
    Height = 13
    Caption = '::'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object btnGet: TButton
    Left = 8
    Top = 355
    Width = 75
    Height = 23
    Anchors = [akLeft, akBottom]
    Caption = 'Get file'
    Enabled = False
    TabOrder = 0
    OnClick = btnGetClick
  end
  object btnPut: TButton
    Left = 89
    Top = 355
    Width = 75
    Height = 23
    Anchors = [akLeft, akBottom]
    Caption = 'Put file'
    Enabled = False
    TabOrder = 1
    OnClick = btnPutClick
  end
  object ListView1: TListView
    Left = 8
    Top = 136
    Width = 692
    Height = 213
    Anchors = [akLeft, akTop, akRight, akBottom]
    Columns = <
      item
        Caption = 'Name'
        Width = 250
      end
      item
        Caption = 'Type'
        Width = 60
      end
      item
        Alignment = taRightJustify
        Caption = 'Size (bytes)'
        Width = 80
      end
      item
        Alignment = taRightJustify
        Caption = 'Perm (octal)'
        Width = 70
      end
      item
        Caption = 'UID/GID'
        Width = 80
      end
      item
        Alignment = taRightJustify
        Caption = 'Lastmod'
        Width = 120
      end>
    GridLines = True
    ReadOnly = True
    RowSelect = True
    TabOrder = 2
    ViewStyle = vsReport
    OnDblClick = ListView1DblClick
  end
  object edHost: TLabeledEdit
    Left = 8
    Top = 24
    Width = 153
    Height = 21
    EditLabel.Width = 26
    EditLabel.Height = 13
    EditLabel.Caption = 'Host:'
    TabOrder = 3
    Text = 'bbox.mshome.net'
  end
  object edPort: TLabeledEdit
    Left = 167
    Top = 24
    Width = 42
    Height = 21
    EditLabel.Width = 24
    EditLabel.Height = 13
    EditLabel.Caption = 'Port:'
    TabOrder = 4
    Text = '22'
  end
  object rbIP4: TRadioButton
    Left = 8
    Top = 51
    Width = 49
    Height = 17
    Caption = 'IPv4'
    Checked = True
    TabOrder = 5
    TabStop = True
  end
  object rbIP6: TRadioButton
    Left = 63
    Top = 51
    Width = 50
    Height = 17
    Caption = 'IPv6'
    TabOrder = 6
  end
  object GroupBox1: TGroupBox
    Left = 542
    Top = 8
    Width = 158
    Height = 109
    Caption = 'Auth mode'
    TabOrder = 7
    object cbTryAll: TCheckBox
      Left = 9
      Top = 16
      Width = 97
      Height = 17
      Caption = 'Try all'
      Checked = True
      State = cbChecked
      TabOrder = 0
      OnClick = cbTryAllClick
    end
    object cbPass: TCheckBox
      Left = 24
      Top = 34
      Width = 97
      Height = 17
      Caption = 'Password'
      Enabled = False
      TabOrder = 1
    end
    object cbKeybInt: TCheckBox
      Left = 24
      Top = 50
      Width = 105
      Height = 17
      Caption = 'Keybd interactive'
      Enabled = False
      TabOrder = 2
    end
    object cbPKey: TCheckBox
      Left = 24
      Top = 67
      Width = 97
      Height = 17
      Caption = 'Public key'
      Enabled = False
      TabOrder = 3
    end
    object cbPKeyAgent: TCheckBox
      Left = 24
      Top = 84
      Width = 114
      Height = 17
      Caption = 'Public key via agent'
      Enabled = False
      TabOrder = 4
    end
  end
  object btnConnect: TButton
    Left = 8
    Top = 74
    Width = 75
    Height = 23
    Caption = 'Connect'
    Default = True
    TabOrder = 8
    OnClick = btnConnectClick
  end
  object btnDisconnect: TButton
    Left = 89
    Top = 74
    Width = 75
    Height = 23
    Caption = 'Disconnect'
    Enabled = False
    TabOrder = 9
    OnClick = btnDisconnectClick
  end
  object edUser: TLabeledEdit
    Left = 224
    Top = 24
    Width = 137
    Height = 21
    EditLabel.Width = 52
    EditLabel.Height = 13
    EditLabel.Caption = 'Username:'
    TabOrder = 10
    Text = 'rain'
  end
  object edPass: TLabeledEdit
    Left = 223
    Top = 62
    Width = 137
    Height = 21
    EditLabel.Width = 50
    EditLabel.Height = 13
    EditLabel.Caption = 'Password:'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
    PasswordChar = #8226
    TabOrder = 11
  end
  object cbKeepAlive: TCheckBox
    Left = 119
    Top = 51
    Width = 65
    Height = 17
    Caption = 'Keepalive'
    Checked = True
    State = cbChecked
    TabOrder = 12
  end
  object btnDelete: TButton
    Left = 170
    Top = 355
    Width = 75
    Height = 23
    Anchors = [akLeft, akBottom]
    Caption = 'Delete'
    Enabled = False
    TabOrder = 13
    OnClick = btnDeleteClick
  end
  object btnRename: TButton
    Left = 251
    Top = 355
    Width = 75
    Height = 23
    Anchors = [akLeft, akBottom]
    Caption = 'Rename'
    Enabled = False
    TabOrder = 14
    OnClick = btnRenameClick
  end
  object btnMkSymlink: TButton
    Left = 332
    Top = 355
    Width = 93
    Height = 23
    Anchors = [akLeft, akBottom]
    Caption = 'Make symlink'
    Enabled = False
    TabOrder = 15
    OnClick = btnMkSymlinkClick
  end
  object btnResSymlink: TButton
    Left = 431
    Top = 355
    Width = 93
    Height = 23
    Anchors = [akLeft, akBottom]
    Caption = 'Resolve symlink'
    Enabled = False
    TabOrder = 16
    OnClick = btnResSymlinkClick
  end
  object btnMkDir: TButton
    Left = 530
    Top = 355
    Width = 95
    Height = 23
    Anchors = [akLeft, akBottom]
    Caption = 'Make directory'
    Enabled = False
    TabOrder = 17
    OnClick = btnMkDirClick
  end
  object StatusBar1: TStatusBar
    Left = 0
    Top = 384
    Width = 708
    Height = 19
    Panels = <
      item
        Width = 600
      end
      item
        Width = 80
      end>
  end
  object edPkey: TLabeledEdit
    Left = 366
    Top = 24
    Width = 137
    Height = 21
    EditLabel.Width = 76
    EditLabel.Height = 13
    EditLabel.Caption = 'Public key path:'
    TabOrder = 19
  end
  object edPrivkey: TLabeledEdit
    Left = 366
    Top = 62
    Width = 137
    Height = 21
    EditLabel.Width = 83
    EditLabel.Height = 13
    EditLabel.Caption = 'Private key path:'
    TabOrder = 20
  end
  object edPrivkpass: TLabeledEdit
    Left = 366
    Top = 100
    Width = 137
    Height = 21
    EditLabel.Width = 116
    EditLabel.Height = 13
    EditLabel.Caption = 'Private key passphrase:'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -11
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
    PasswordChar = #8226
    TabOrder = 21
  end
  object btnSelPkey: TButton
    Left = 507
    Top = 24
    Width = 25
    Height = 21
    Caption = '...'
    TabOrder = 22
    OnClick = btnSelPkeyClick
  end
  object btnSelPrivkey: TButton
    Left = 507
    Top = 62
    Width = 25
    Height = 21
    Caption = '...'
    TabOrder = 23
    OnClick = btnSelPrivkeyClick
  end
  object btnSetPerms: TButton
    Left = 631
    Top = 355
    Width = 69
    Height = 23
    Anchors = [akLeft, akBottom]
    Caption = 'Set perms'
    Enabled = False
    TabOrder = 24
  end
end
