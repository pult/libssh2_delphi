unit Unit3;

interface

uses
  {$IFDEF UNICODE}
  System.UITypes,
  {$ENDIF}
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, uMySFTPClient,
  StdCtrls, ComCtrls, ExtCtrls, CheckLst;

type
  TForm3 = class(TForm)
    btnGet: TButton;
    btnPut: TButton;
    ListView1: TListView;
    lblCurDir: TLabel;
    edHost: TLabeledEdit;
    edPort: TLabeledEdit;
    rbIP4: TRadioButton;
    rbIP6: TRadioButton;
    GroupBox1: TGroupBox;
    cbTryAll: TCheckBox;
    cbPass: TCheckBox;
    cbKeybInt: TCheckBox;
    cbPKey: TCheckBox;
    cbPKeyAgent: TCheckBox;
    btnConnect: TButton;
    btnDisconnect: TButton;
    edUser: TLabeledEdit;
    edPass: TLabeledEdit;
    cbKeepAlive: TCheckBox;
    btnDelete: TButton;
    btnRename: TButton;
    btnMkSymlink: TButton;
    btnResSymlink: TButton;
    btnMkDir: TButton;
    StatusBar1: TStatusBar;
    edPkey: TLabeledEdit;
    edPrivkey: TLabeledEdit;
    edPrivkpass: TLabeledEdit;
    btnSelPkey: TButton;
    btnSelPrivkey: TButton;
    btnSetPerms: TButton;
    procedure FormCreate(Sender: TObject);
    procedure btnConnectClick(Sender: TObject);
    procedure ListView1DblClick(Sender: TObject);
    procedure btnDisconnectClick(Sender: TObject);
    procedure btnMkDirClick(Sender: TObject);
    procedure btnResSymlinkClick(Sender: TObject);
    procedure btnMkSymlinkClick(Sender: TObject);
    procedure btnRenameClick(Sender: TObject);
    procedure btnDeleteClick(Sender: TObject);
    procedure btnPutClick(Sender: TObject);
    procedure btnGetClick(Sender: TObject);
    procedure btnSelPkeyClick(Sender: TObject);
    procedure btnSelPrivkeyClick(Sender: TObject);
    procedure cbTryAllClick(Sender: TObject);
  private
    SFTP: TSFTPClient;
    procedure FillList;
    procedure OnProgress(ASender: TObject; const AFileName: WideString; ATransfered, ATotal: UInt64);
    procedure OnCantChangeStartDir(ASender: TObject; var Continue: Boolean);
    procedure OnAuthFailed(ASender: TObject; var Continue: Boolean);
    procedure OnKeybdInteractive(ASender: TObject; var Password: String);

    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form3: TForm3;

implementation

uses
  WideStrUtils, FileCtrl, libssh2_sftp, Unit4;

var
  ProgressFrm: TFrmProgress;
{$R *.dfm}

procedure TForm3.btnConnectClick(Sender: TObject);
var
  Mode: TAuthModes;
begin
  SFTP.UserName := edUser.Text;
  SFTP.Password := edPass.Text;
  SFTP.Host := edHost.Text;
  SFTP.Port := StrToIntDef(edPort.Text, 22);
  SFTP.KeepAlive := cbKeepAlive.Checked;
  if rbIP4.Checked then
    SFTP.IPVersion := IPv4
  else
    SFTP.IPVersion := IPv6;

  if cbTryAll.Checked then
    SFTP.AuthModes := [amTryAll]
  else
  begin
    Mode := [];
    if cbPass.Checked then
      Mode := Mode + [amPassword];
    if cbKeybInt.Checked then
      Mode := Mode + [amKeyboardInteractive];
    if cbPKey.Checked then
      Mode := Mode + [amPublicKey];
    if cbPKeyAgent.Checked then
      Mode := Mode + [amPublicKeyViaAgent];
    if Mode = [] then
    begin
      ShowMessage('You must select at least one auth mode.');
      Exit;
    end;
    SFTP.AuthModes := Mode;
  end;
  SFTP.PublicKeyPath := edPkey.Text;
  SFTP.PrivateKeyPath := edPrivkey.Text;
  SFTP.PrivKeyPassPhrase := edPrivkpass.Text;
  try
    SFTP.Connect;
    if not SFTP.Connected then
      Exit;
    StatusBar1.Panels[0].Text := SFTP.GetSessionMethodsStr;
    SFTP.List;
    FillList;
    btnConnect.Enabled := False;
    btnDisconnect.Enabled := SFTP.Connected;

    btnGet.Enabled := True;
    btnPut.Enabled := True;
    btnDelete.Enabled := True;
    btnRename.Enabled := True;
    btnMkSymlink.Enabled := True;
    btnResSymlink.Enabled := True;
    btnMkDir.Enabled := True;
    btnSetPerms.Enabled := True;

  except
    on E: ESSH2Exception do
      ShowMessage(E.Message);
  end;
end;

procedure TForm3.btnDisconnectClick(Sender: TObject);
begin
  SFTP.Disconnect;
  ListView1.Clear;
  btnConnect.Enabled := True;
  btnDisconnect.Enabled := False;
  lblCurDir.Caption := '::';
  StatusBar1.Panels[0].Text := '';
  btnGet.Enabled := False;
  btnPut.Enabled := False;
  btnDelete.Enabled := False;
  btnRename.Enabled := False;
  btnMkSymlink.Enabled := False;
  btnResSymlink.Enabled := False;
  btnMkDir.Enabled := False;
  btnSetPerms.Enabled := False;
end;

procedure TForm3.btnGetClick(Sender: TObject);
var
  Dir: String;
  FS: TFileStream;
  I: Integer;
begin
  if ListView1.SelCount = 1 then
    if ListView1.Selected.Caption <> '..' then
    begin
      if SelectDirectory('Select dir where to save the file', '.', Dir) then
      begin
        I := ListView1.Selected.Index;
        if ListView1.Items[0].Caption = '..' then
          Dec(I);

        // process "file" items only, on the otherside
        // if the item is symlink, then we could resolve it and
        // follow the path
        if SFTP.DirectoryItems[I].ItemType <> sitFile then
        begin
          ShowMessage('Select file first.');
          Exit;
        end;
        // the code below is put in a tworkerthread in the original program
        // this is just a demo, so :P
        FS := TFileStream.Create(Dir + '\' + SFTP.DirectoryItems[I].FileName, fmCreate);
        if ProgressFrm = nil then
          ProgressFrm := TFrmProgress.Create(Self);
        try
          ProgressFrm.Caption := 'Getting file...';
          ProgressFrm.Show;
          try
            SFTP.Get(SFTP.CurrentDirectory + '/' + SFTP.DirectoryItems[I].FileName, FS, False)
          except on E: ESSH2Exception do
            ShowMessage(E.Message);
          end;
        finally
          ProgressFrm.Close;
          FS.Free;
        end;
      end;
    end;
end;

procedure TForm3.btnPutClick(Sender: TObject);
var
  FS: TFileStream;
begin
  with TOpenDialog.Create(Self) do
  begin
    Title := 'Select file';
    Filter := '*.*';
    if Execute(Handle) then
    begin
      // the code below is put in a tworkerthread in the original program
      // this is just a demo, so :P
      FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
      if ProgressFrm = nil then
        ProgressFrm := TFrmProgress.Create(Self);
      try
        ProgressFrm.Caption := 'Putting file...';
        ProgressFrm.Show;
        try
          SFTP.Put(FS, SFTP.CurrentDirectory + '/' + ExtractFileName(FileName));
          SFTP.List;
          FillList;
        except
          on E: ESSH2Exception do
            ShowMessage(E.Message);
        end;
      finally
        ProgressFrm.Close;
        FS.Free;
      end;
    end;
    Free;
  end;
end;

procedure TForm3.btnDeleteClick(Sender: TObject);
var
  I: Integer;
begin
  if ListView1.SelCount = 1 then
    if ListView1.Selected.Caption <> '..' then
    begin
      if MessageDlg('Are you sure?', mtWarning, mbYesNo, 0) = mrNo then
        Exit;
      I := ListView1.Selected.Index;
      if ListView1.Items[0].Caption = '..' then
        Dec(I);
      try
        if SFTP.DirectoryItems[I].ItemType = sitDirectory then
          SFTP.DeleteDir(SFTP.CurrentDirectory + '/' + SFTP.DirectoryItems[I].FileName)
        else
          SFTP.DeleteFile(SFTP.CurrentDirectory + '/' + SFTP.DirectoryItems[I].FileName);

        SFTP.List;
        FillList;
      except
        on E: ESSH2Exception do
          ShowMessage(E.Message);
      end;
    end;
end;

procedure TForm3.btnRenameClick(Sender: TObject);
var
  I: Integer;
  NewName: String;
begin
  if ListView1.SelCount = 1 then
    if ListView1.Selected.Caption <> '..' then
    begin
      I := ListView1.Selected.Index;
      if ListView1.Items[0].Caption = '..' then
        Dec(I);
      NewName := SFTP.DirectoryItems[I].FileName;
      if InputQuery('Rename', 'Enter new name', NewName) then
        try
          SFTP.Rename(SFTP.DirectoryItems[I].FileName, SFTP.CurrentDirectory + '/' + NewName);
          SFTP.List;
          FillList;
        except
          on E: ESSH2Exception do
            ShowMessage(E.Message);
        end;
    end;
end;

procedure TForm3.btnMkSymlinkClick(Sender: TObject);
var
  ATarget, AName: String;
begin
  //
  ATarget := '';
  if ListView1.SelCount = 1 then
    if ListView1.Selected.Caption <> '..' then
      ATarget := SFTP.CurrentDirectory + '/' + ListView1.Selected.Caption;
  if InputQuery('Link target', 'Enter link target', ATarget) then
    if InputQuery('Link name', 'Enter link name', AName) then
      try
        SFTP.MakeSymLink(SFTP.CurrentDirectory + '/' + AName, ATarget);
        SFTP.List;
        FillList;
      except
        on E: ESSH2Exception do
          ShowMessage(E.Message);
      end;
end;

procedure TForm3.btnResSymlinkClick(Sender: TObject);
var
  A: LIBSSH2_SFTP_ATTRIBUTES;
  I: Integer;
  S, S1: WideString;
begin
  //
  if SFTP.Connected and (ListView1.SelCount = 1) then
  begin
    try
      if ListView1.Selected.Caption <> '..' then
      begin
        I := ListView1.Selected.Index;
        if ListView1.Items[0].Caption = '..' then
          Dec(I);

        if SFTP.DirectoryItems[I].ItemType in [sitSymbolicLink, sitSymbolicLinkDir] then
        begin
          S := SFTP.ResolveSymLink(SFTP.CurrentDirectory + '/' + ListView1.Selected.Caption, A);
          S1 := SFTP.ResolveSymLink(SFTP.CurrentDirectory + '/' + ListView1.Selected.Caption, A,
            True);
          ShowMessage('Links to: ' + S + #13#10 + 'Realpath: ' + S1);
        end;
      end;
    except
      on E: ESSH2Exception do
        ShowMessage(E.Message);
    end;
  end;
end;

procedure TForm3.btnSelPkeyClick(Sender: TObject);
begin
  with TOpenDialog.Create(Self) do
  begin
    Title := 'Select public key file';
    Filter := '*.*';
    if Execute(Handle) then
      edPkey.Text := FileName;
    Free;
  end;
end;

procedure TForm3.btnSelPrivkeyClick(Sender: TObject);
begin
  with TOpenDialog.Create(Self) do
  begin
    Title := 'Select private key file';
    Filter := '*.*';
    if Execute(Handle) then
      edPrivkey.Text := FileName;
    Free;
  end;
end;

procedure TForm3.cbTryAllClick(Sender: TObject);
begin
  cbPass.Enabled := not cbTryAll.Checked;
  cbKeybInt.Enabled := not cbTryAll.Checked;
  cbPKey.Enabled := not cbTryAll.Checked;
  cbPKeyAgent.Enabled := not cbTryAll.Checked;
end;

procedure TForm3.btnMkDirClick(Sender: TObject);
var
  Dir: string;
begin
  if InputQuery('Create directory', 'Directory name', Dir) then
  begin
    SFTP.MakeDir(SFTP.CurrentDirectory + '/' + Dir);
    SFTP.List;
    FillList;
  end;
end;

procedure TForm3.FillList;
  function ItemTypeToStr(AType: TSFTPItemType): String;
  begin
    Result := '';
    case AType of
      sitUnknown:
        Result := 'unknown';
      sitDirectory:
        Result := '<DIR>';
      sitFile:
        Result := 'file';
      sitSymbolicLink:
        Result := 'symlink';
      sitSymbolicLinkDir:
        Result := '<LNK>';
      sitBlockDev:
        Result := 'block';
      sitCharDev:
        Result := 'char';
      sitFIFO:
        Result := 'fifo';
      sitSocket:
        Result := 'socket';
    end;
  end;

var
  I: Integer;
  Item: TListItem;
  SFTPItem: TSFTPItem;
begin
  lblCurDir.Caption := SFTP.CurrentDirectory;
  ListView1.Clear;
  ListView1.Items.BeginUpdate;
  SFTP.DirectoryItems.SortDefault;
  if SFTP.CurrentDirectory <> '/' then
    ListView1.AddItem('..', nil);
  for I := 0 to SFTP.DirectoryItems.Count - 1 do
  begin
    SFTPItem := SFTP.DirectoryItems[I];
    Item := ListView1.Items.Add;
    Item.Caption := SFTPItem.FileName;
    Item.SubItems.Add(ItemTypeToStr(SFTPItem.ItemType));
    Item.SubItems.Add(IntToStr(SFTPItem.FileSize));
    Item.SubItems.Add(SFTPItem.PermsOctal);
    Item.SubItems.Add(SFTPItem.UIDStr + '-' + SFTPItem.GIDStr);
    Item.SubItems.Add(DateTimeToStr(SFTPItem.LastModificationTime));
  end;
  ListView1.Items.EndUpdate;
end;

procedure TForm3.FormCreate(Sender: TObject);
begin
  //
  {$IFDEF CPUX64}
  Caption := Caption + ' (x64)';
  {$ENDIF}
  //
  SFTP := TSFTPClient.Create(Self);
  SFTP.DebugMode := True; // ouput debug info over Windows.OutputDebugString
  SFTP.OnTransferProgress := OnProgress;
  SFTP.OnAuthFailed := OnAuthFailed;
  SFTP.OnCantChangeStartDir := OnCantChangeStartDir;
  SFTP.OnKeybdInteractive := OnKeybdInteractive;
  StatusBar1.Panels[1].Text := 'libssh2 ver: ' + SFTP.LibraryVersion;
end;

procedure TForm3.ListView1DblClick(Sender: TObject);
var
  W: WideString;
  Item: TListItem;
  A: LIBSSH2_SFTP_ATTRIBUTES;
  I: Integer;
begin
  //
  if ListView1.SelCount = 1 then
  begin
    try
      Item := ListView1.Selected;
      if Item.Caption = '..' then
      begin
        W := ExtractFileDir(WideStringReplace(SFTP.CurrentDirectory, '/', '\', [rfReplaceAll,
            rfIgnoreCase]));
        if W = '' then
          W := '/'
        else
          W := WideStringReplace(W, '\', '/', [rfReplaceAll, rfIgnoreCase]);
        SFTP.List(W);
        FillList;
        Exit;
      end;

      I := Item.Index;
      if (I <> 0) and (ListView1.Items[0].Caption = '..') then
        Dec(I);
      if SFTP.DirectoryItems[I].ItemType in [sitDirectory, sitSymbolicLinkDir] then
      begin
        if SFTP.DirectoryItems[I].ItemType = sitSymbolicLinkDir then
        begin
          W := SFTP.ResolveSymLink(SFTP.CurrentDirectory + '/' + Item.Caption, A, True);
          if W = '' then
            W := '/';
          SFTP.List(W);
        end
        else
        begin
          W := SFTP.CurrentDirectory;
          if W = '/' then
            W := '';
          SFTP.List(W + '/' + Item.Caption);
        end;
        FillList;
      end;

    except
      on E: ESSH2Exception do
        ShowMessage(E.Message);
    end;
  end;
end;

procedure TForm3.OnAuthFailed(ASender: TObject; var Continue: Boolean);
begin
  Continue := MessageDlg('Auth failed. Try again?', mtConfirmation, mbYesNo, 0) = mrYes;
end;

procedure TForm3.OnCantChangeStartDir(ASender: TObject; var Continue: Boolean);
begin
  Continue := MessageDlg('Could not change to start dir. Continue?', mtConfirmation, mbYesNo, 0) = mrYes;
end;

procedure TForm3.OnKeybdInteractive(ASender: TObject; var Password: String);
begin
  InputQuery('Enter password for kybdinteractive', 'Password', Password);
end;

procedure TForm3.OnProgress(ASender: TObject; const AFileName: WideString; ATransfered, ATotal: UInt64);
begin
  //
  if Assigned(ProgressFrm) then
  begin
    ProgressFrm.ProgressBar1.Max := ATotal;
    ProgressFrm.ProgressBar1.Position := ATransfered;
    ProgressFrm.Label1.Caption := AFileName;
    ProgressFrm.Update;
    Application.ProcessMessages;
    if ProgressFrm.ModalResult = mrCancel then
      SFTP.Cancel(False);
    if ATransfered >= ATotal then
      ProgressFrm.ModalResult := mrOk;
  end;
end;

end.
