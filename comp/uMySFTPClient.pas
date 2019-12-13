{ **
  *  Copyright (c) 2010, Zeljko Marjanovic <savethem4ever@gmail.com>
  *  This code is licensed under MPL 1.1
  *  For details, see http://www.mozilla.org/MPL/MPL-1.1.html
  * }
{ **
  *  Delphi/Pascal Wrapper around the library "libssh2"
  *    Base repository:
  *      https://bitbucket.org/ZeljkoMarjanovic/libssh2-delphi
  *        Contributors:
  *          https://bitbucket.org/jeroenp/libssh2-delphi
  *          https://github.com/pult/libssh2_delphi/
  *          https://bitbucket.org/VadimLV/libssh2_delphi
  * }
unit uMySFTPClient;

{$i libssh2.inc}

interface

uses
  {$IFDEF allow_hvdll}
  HVDll, // alternative for: external ?dll_name name '?function_name' delayed;
  {$ENDIF}
  {$IFDEF WIN32}
  Windows,
  {$ELSE}
  Wintypes, WinProcs,
  {$ENDIF}
  Classes, SysUtils, WinSock, libssh2, libssh2_sftp;

const
  AF_INET6 = 23;
  SFTPCLIENT_VERSION = '0.5';

type
  TSFTPItemType = (sitUnknown, sitDirectory, sitFile, sitSymbolicLink, sitSymbolicLinkDir,
    sitBlockDev, sitCharDev, sitFIFO, sitSocket);
  TIPVersion = (IPvUNSPEC = 0, IPv4 = AF_INET, IPv6 = AF_INET6);
  TAuthMode = (amTryAll, amPassword, amPublicKey, amKeyboardInteractive, amPublicKeyViaAgent);
  TAuthModes = set of TAuthMode;
  TFingerprintState = (fsNew, fsChanged);
  TConnectHashAction = (chaCancel, chaIgnore, chaSave);
  TFingerprintEvent = procedure(ASender: TObject; const AState: TFingerprintState;
    var AAction: TConnectHashAction) of object;
  TKeybInteractiveEvent = procedure(ASender: TObject; var Password: string) of object;
  TTransferProgress = procedure(ASender: TObject; const AFileName: WideString;
    ATransfered, ATotal: UInt64) of object;
  TContinueEvent = procedure(ASender: TObject; var ACountinue: Boolean) of object;

  EWorkThreadException = class(Exception);
  ESSH2Exception = class(Exception);

  PAddrInfo = ^addrinfo;
    addrinfo = record
    ai_flags: Integer; // AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST
    ai_family: Integer; // PF_xxx
    ai_socktype: Integer; // SOCK_xxx
    ai_protocol: Integer; // 0 or IPPROTO_xxx for IPv4 and IPv6
    ai_addrlen: ULONG; // Length of ai_addr
    ai_canonname: PAnsiChar; // Canonical name for nodename
    ai_addr: PSockAddr; // Binary address
    ai_next: PAddrInfo; // Next structure in linked list
  end;

  TStructStat = struct_stat;
  PStructStat = ^TStructStat;

  TWorkThread = class(TThread)
  private
    FInterval: Cardinal;
    FNEvent: TNotifyEvent;
    FSender: TObject;
    FCanceled: Boolean;
    FEvent: THandle;
    FInEvent: THandle;
    FSyncExecute: Boolean;
    FEnabled: Boolean;
    FData: Pointer;
  protected
    procedure Execute; override;
    procedure Trigger;
  public
    constructor Create(const CreateSuspended: Boolean);
    destructor Destroy; override;
    procedure Terminate; overload;
    procedure Start;
    procedure Stop;
    property Interval: Cardinal Read FInterval Write FInterval;
    property Event: TNotifyEvent Read FNEvent Write FNEvent;
    property ThreadSender: TObject Read FSender Write FSender;
    property Data: Pointer read FData write FData;
    property SyncExecute: Boolean read FSyncExecute write FSyncExecute;
  end;

  TSFTPStatData = class(TCollectionItem)
  private
    FFileSize: UInt64;
    FUid: UInt;
    FGid: UInt;
    FPerms: Cardinal;
    FAtime: TDateTime;
    FMtime: TDateTime;
  protected
  published
    property FileSize: UInt64 read FFileSize write FFileSize;
    property UID: UInt read FUid write FUid;
    property GID: UInt read FGid write FGid;
    property Permissions: Cardinal read FPerms write FPerms;
    property LastAccessTime: TDateTime read FAtime write FAtime;
    property LastModificationTime: TDateTime read FMtime write FMtime;
  end;

  TSFTPItem = class(TSFTPStatData)
  private
    FFileName: WideString;
    FLinkPath: WideString;
    FItemType: TSFTPItemType;
    FLinkSize: UInt64;
    FHidden: Boolean;
    FGIDStr: WideString;
    FUIDStr: WideString;
    function GetPermsOct: string;
    procedure SetPermsOct(const Value: string);
  protected
  published
    procedure Assign(ASource: TPersistent); override;
    property FileName: WideString read FFileName write FFileName;
    property LinkPath: WideString read FLinkPath write FLinkPath;
    property LinkSize: UInt64 read FLinkSize write FLinkSize;
    property Hidden: Boolean read FHidden write FHidden;
    property UIDStr: WideString read FUIDStr write FUIDStr;
    property GIDStr: WideString read FGIDStr write FGIDStr;
    property PermsOctal: string read GetPermsOct write SetPermsOct;
    property ItemType: TSFTPItemType read FItemType write FItemType;
  end;

  TSFTPItems = class(TCollection)
  private
    FOwner: TComponent;
    FPath: WideString;
    function GetItems(const AIndex: Integer): TSFTPItem;
    procedure SetItems(const AIndex: Integer; const Value: TSFTPItem);
  protected
    function GetOwner: TPersistent; override;
  public
    constructor Create(AOwner: TComponent);
    function Add: TSFTPItem;
    function IndexOf(const AItem: TSFTPItem): Integer;
    procedure ParseEntryBuffers(ABuffer, ALongEntry: PAnsiChar;
      const AAttributes: LIBSSH2_SFTP_ATTRIBUTES; ACodePage: Word = CP_UTF8);
    procedure SortDefault;
    property Path: WideString read FPath write FPath;
    property Items[const AIndex: Integer]: TSFTPItem read GetItems write SetItems; default;
  end;

  THashMode = (hmMD5, hmSHA1);

  IHashManager = interface
    ['{296711A3-DE46-4674-9160-382A6F7D87A0}']
    function GetFingerprint(const AHost: string; APort: Word): Pointer; overload;
    function StoreFingerprint(const AHost: string; APort: Word; const AHash: Pointer): Boolean;
    function RemoveFingerprint(const AHost: string; APort: Word; const AHash: Pointer): Boolean;
    function CompareFingerprints(const F1, F2: Pointer): Boolean;
    function GetHashMode: THashMode;
  end;

  TSSH2Client = class(TComponent)
  private
    FDebugMode: Boolean;
    FPrivKeyPass: string;
    FPrivKeyPath: TFileName;
    FAuthModes: TAuthModes;
    FPubKeyPath: TFileName;
    FPort: Word;
    FPassword: string;
    FHost: string;
    FUserName: string;
    FIPVersion: TIPVersion;
    FClientBanner: string;
    FConnected: Boolean;
    FCanceled: Boolean;
    FLastErrStr: string;
    FKeepAlive: Boolean;
    FTimeOut: Integer; // keepalive timeout interval in seconds
    FSockBufLen: Integer;
    FHashMgr: IHashManager;
    FSocket: Integer;
    FSession: PLIBSSH2_SESSION;
    FOnFingerprint: TFingerprintEvent;
    FOnKeybInt: TKeybInteractiveEvent;
    FOnAuthFail: TContinueEvent;
    FOnConnect: TNotifyEvent;
    FCodePage: Word;
    FCompression: Boolean;
    function GetConnected: Boolean;
    procedure SetConnected(const Value: Boolean);
    procedure SetAuthModes(const Value: TAuthModes);
    procedure DoOnFingerprint(const AState: TFingerprintState; var AAction: TConnectHashAction);
    function GetVersion: string;
    function GetLibString: string;
  protected
    function GetSessionPtr: PLIBSSH2_SESSION;
    function GetSocketHandle: Integer;
    function CreateSocket: Integer; virtual;
    function ConnectSocket(var S: Integer): Boolean; virtual;
    procedure RaiseSSHError(const AMsg: string = ''; E: Integer = 0); virtual;
    function MyEncode(const WS: WideString): AnsiString; virtual;
    function MyDecode(const S: AnsiString): WideString; virtual;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    procedure Connect; virtual;
    procedure Disconnect; virtual;
    function GetLastSSHError(E: Integer = 0): string; virtual;
    procedure Cancel(ADisconnect: Boolean = True); virtual;
    function GetSessionMethodsStr: string;

    property DebugMode: Boolean read FDebugMode write FDebugMode default False;
    property Host: string read FHost write FHost;
    property Port: Word read FPort write FPort default 22;
    property IPVersion: TIPVersion read FIPVersion write FIPVersion;
    property KeepAlive: Boolean read FKeepAlive write FKeepAlive;
    property TimeOut: Integer read FTimeOut write FTimeOut;
    property SockSndRcvBufLen: Integer read FSockBufLen write FSockBufLen;
    property AuthModes: TAuthModes read FAuthModes write SetAuthModes default [amTryAll];
    property UserName: string read FUserName write FUserName;
    property Password: string read FPassword write FPassword;
    property PublicKeyPath: TFileName read FPubKeyPath write FPubKeyPath;
    property PrivateKeyPath: TFileName read FPrivKeyPath write FPrivKeyPath;
    property PrivKeyPassPhrase: string read FPrivKeyPass write FPrivKeyPass;
    property ClientBanner: string read FClientBanner write FClientBanner;
    property HashManager: IHashManager read FHashMgr write FHashMgr;
    property Connected: Boolean read GetConnected write SetConnected;
    property LibraryVersion: string read GetLibString;
    property Compression: Boolean read FCompression write FCompression;

    property CodePage: Word read FCodePage write FCodePage default CP_UTF8;

    property OnFingerprint: TFingerprintEvent read FOnFingerprint write FOnFingerprint;
    property OnKeybdInteractive: TKeybInteractiveEvent read FOnKeybInt write FOnKeybInt;
    property OnConnected: TNotifyEvent read FOnConnect write FOnConnect;
    property OnAuthFailed: TContinueEvent read FOnAuthFail write FOnAuthFail;
    property Version: string read GetVersion;
  end;

  TSFTPClient = class(TSSH2Client)
  private
    FCurrentDir: string;
    FItems: TSFTPItems;
    FCanceled: Boolean;
    FSFtp: PLIBSSH2_SFTP;
    FLastDirChangedOK: Boolean;
    FOnTProgress: TTransferProgress;
    FOnNoStartDir: TContinueEvent;
    FReadBufLen: Cardinal;
    FWriteBufLen: Cardinal;
    procedure SetCurrentDir(const Value: string);
    procedure DoMakeDir(const LDir: WideString; AMode: Integer = 0; ARecurse: Boolean = False);
  protected
    procedure RaiseSSHError(const AMsg: string = ''; E: Integer = 0); override;
    function ChangeDir(const APath: WideString): Boolean;
  public
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;

    procedure Connect(const ARemoteDir: WideString = '.'); reintroduce;
    procedure Disconnect; override;
    function GetLastSSHError(E: Integer = 0): string; override;
    procedure Cancel(ADisconnect: Boolean = True); override;

    procedure List(const AStartPath: WideString = '');
    procedure DeleteFile(const AFileName: WideString);
    procedure DeleteDir(const ADirName: WideString);
    procedure MakeDir(const ADirName: WideString; AMode: Integer = 0; ARecurse: Boolean = False);
    {+}
    function OpenDir(const APath: WideString; AutoMake: Boolean = False; MakeMode: Integer = 0): Boolean;
    function Exists(const ASourceFileName: WideString): Boolean;
    {+.}
    procedure Get(const ASourceFileName: WideString; const ADest: TStream; AResume: Boolean);
    procedure Put(const ASource: TStream; const ADestFileName: WideString;
      AOverwrite: Boolean = False); // TODO: AResume: Boolean;
    procedure Rename(const AOldName, ANewName: WideString);
    procedure MakeSymLink(const AOrigin, ADest: WideString);
    function ResolveSymLink(const AOrigin: WideString; var AAtributes: LIBSSH2_SFTP_ATTRIBUTES;
      ARealPath: Boolean = False): string;
    procedure SetAttributes(const APath: WideString; AAtribs: LIBSSH2_SFTP_ATTRIBUTES);
    procedure SetPermissions(const APath: WideString; APerms: Cardinal); overload;
    procedure SetPermissions(const APath: WideString; const AOctalPerms: string); overload;
    function ExpandCurrentDirPath: WideString;

    property ReadBufferLen: Cardinal read FReadBufLen write FReadBufLen;
    property WriteBufferLen: Cardinal read FWriteBufLen write FWriteBufLen;

    property DirectoryItems: TSFTPItems read FItems;
    property CurrentDirectory: string read FCurrentDir write SetCurrentDir;

    property OnCantChangeStartDir: TContinueEvent read FOnNoStartDir write FOnNoStartDir;
    property OnTransferProgress: TTransferProgress read FOnTProgress write FOnTProgress;
  end;

  TSCPClient = class(TSSH2Client)
  private
    FCanceled: Boolean;
    FOnTProgress: TTransferProgress;
  protected
  public
    procedure Cancel(ADisconnect: Boolean = True); override;
    procedure Get(const ASourceFileName: WideString; const ADest: TStream; var AStat: TStructStat);
    procedure Put(const ASource: TStream; const ADestFileName: WideString; AFileSize: UInt64;
      ATime, MTime: TDateTime; AMode: Integer = 0);
    property OnTransferProgress: TTransferProgress read FOnTProgress write FOnTProgress;
  end;

function ToOctal(X: Cardinal; const Len: Integer = 4): string;
function FromOctal(const S: string): Cardinal;
function EncodeStr(const WS: WideString; ACodePage: Word = CP_UTF8): AnsiString;
function DecodeStr(const S: AnsiString; ACodePage: Word = CP_UTF8): WideString;

implementation

uses
  DateUtils, Forms, StrUtils, WideStrUtils;

procedure dbg(const S: string); inline;
begin
  {$IFDEF MSWINDOWS}
  if Length(S) > 0 then OutputDebugString(PChar('libssh2:> ' + S));
  {$ENDIF}
end;

procedure dbgw(const S: WideString); inline;
begin
  {$IFDEF MSWINDOWS}
  if Length(S) > 0 then OutputDebugStringW(PWideChar('libssh2:> ' + S));
  {$ENDIF}
end;

var
  GSSH2Init: Integer;

const
  dll_ws2_32_name = 'ws2_32.dll';

{$if declared(uHVDll)}
var
connect2 : function(S: TSocket; name: Pointer; namelen: Integer): Integer; stdcall;
  // external dll_ws2_32_name name 'connect';

getaddrinfo : function(pNodeName, pServiceName: PAnsiChar; const pHints: PAddrInfo;
  var ppResult: PAddrInfo): Integer; stdcall;
  // external dll_ws2_32_name name 'getaddrinfo';

freeaddrinfo : procedure(ai: PAddrInfo); stdcall;
  // external dll_ws2_32_name name 'freeaddrinfo';

  dll_ws2_32 : TDll;
  dll_ws2_32_entires : array[0..2] of HVDll.TEntry = (
    (Proc: @@connect2;     Name: 'connect'),
    (Proc: @@getaddrinfo;  Name: 'getaddrinfo'),
    (Proc: @@freeaddrinfo; Name: 'freeaddrinfo')
  );
{$else !declared(uHVDll)}

{$ifdef allow_delayed}
  {$WARN SYMBOL_PLATFORM OFF} // W002
{$endif}

function connect2(S: TSocket; name: Pointer; namelen: Integer): Integer; stdcall;
  external dll_ws2_32_name name 'connect'{$ifdef allow_delayed} delayed{$endif};

function getaddrinfo(pNodeName, pServiceName: PAnsiChar; const pHints: PAddrInfo;
  var ppResult: PAddrInfo): Integer; stdcall; external dll_ws2_32_name name 'getaddrinfo'
  {$ifdef allow_delayed} delayed{$endif};

procedure freeaddrinfo(ai: PAddrInfo); stdcall; external dll_ws2_32_name name 'freeaddrinfo'
  {$ifdef allow_delayed} delayed{$endif};
{$ifend !declared(uHVDll)}

function TestBit(const ABits, AVal: Cardinal): Boolean; inline;
begin
  Result := ABits and AVal { = AVal } <> 0;
end;

procedure ProcessMsgs;
begin
  Application.ProcessMessages;
end;

function FromOctal(const S: string): Cardinal;
var
  I: Cardinal;
begin
  Result := 0;
  for I := 1 to Length(S) do
    Result := Result * 8 + Cardinal(StrToIntDef(Copy(S, I, 1), 0));
end;

function ToOctal(X: Cardinal; const Len: Integer): string;
var
  M: Integer;
begin
  if X = 0 then
  begin
    Result := '0';
    Exit;
  end;
  Result := '';
  while X <> 0 do
  begin
    M := X mod 8;
    X := X div 8;
    Result := IntToStr(M) + Result;
  end;
  if Len > 0 then
    // Result := Format('%.'+IntToStr(Len)+'d', [StrToIntDef(Result, 0)]);
    Result := Copy(Result, Length(Result) - Len + 1, Len);
end;

function EncodeStr(const WS: WideString; ACodePage: Word): AnsiString;
var
  L: Integer;
  Flags: Cardinal;
begin
  if ACodePage = CP_UTF8 then
  begin
    Result := UTF8Encode(WS);
    Exit;
  end;

  Result := '';
  Flags := 0; // WC_COMPOSITECHECK;
  L := WideCharToMultiByte(ACodePage, Flags, @WS[1], -1, nil, 0, nil, nil);
  if L > 1 then
  begin
    SetLength(Result, L - 1);
    WideCharToMultiByte(ACodePage, Flags, @WS[1], -1, @Result[1], L - 1, nil, nil)
  end;
end;

function DecodeStr(const S: AnsiString; ACodePage: Word): WideString;
var
  L: Integer;
  Flags: Cardinal;
begin
  if ACodePage = CP_UTF8 then
  begin
    {$IFDEF UNICODE} // TODO: FPC Check
    Result := UTF8ToWideString(S);
    {$ELSE}
    Result := UTF8Decode(S);
    {$ENDIF}
    Exit;
  end;

  Result := '';
  Flags := MB_PRECOMPOSED;
  L := MultiByteToWideChar(ACodePage, Flags, PAnsiChar(@S[1]), -1, nil, 0);
  if L > 1 then
  begin
    SetLength(Result, L - 1);
    MultiByteToWideChar(ACodePage, Flags, PAnsiChar(@S[1]), -1, PWideChar(@Result[1]), L - 1);
  end;
end;

{ TSFTPItem }

procedure TSFTPItem.Assign(ASource: TPersistent);
var
  X: TSFTPItem;
begin
  if ASource is TSFTPItem then
  begin
    X := TSFTPItem(ASource);
    Self.FFileName := X.FFileName;
    Self.FLinkPath := X.FLinkPath;
    Self.FItemType := X.FItemType;
    Self.FLinkSize := X.FLinkSize;
    Self.FHidden := X.FHidden;
    Self.FGIDStr := X.FGIDStr;
    Self.FUIDStr := X.FUIDStr;
    Self.FPerms := X.FPerms;
    Self.FAtime := X.FAtime;
    Self.FMtime := X.FMtime;
    Self.FFileSize := X.FFileSize;
    Self.FUid := X.FUid;
    Self.FGid := X.FGid;
  end
  else
    inherited Assign(ASource);
end;

function TSFTPItem.GetPermsOct: string;
begin
  Result := ToOctal(Permissions)
end;

procedure TSFTPItem.SetPermsOct(const Value: string);
begin
  Permissions := FromOctal(Value)
end;

{ TWorkThread }

constructor TWorkThread.Create(const CreateSuspended: Boolean);
begin
  inherited Create(CreateSuspended);
  FEnabled := not CreateSuspended;
  FreeOnTerminate := False;
  FInterval := INFINITE;
  FNEvent := nil;
  FSender := nil;
  FCanceled := False;
  FSyncExecute := True;
  FEvent := CreateEvent(nil, True, False, nil);
  FInEvent := CreateEvent(nil, True, False, nil);
  if (FEvent = 0) or (FInEvent = 0) then
    raise EWorkThreadException.Create('Could not create events.');
end;

destructor TWorkThread.Destroy;
begin
  SetEvent(FEvent);
  FCanceled := True;
  CloseHandle(FEvent);
  CloseHandle(FInEvent);
  inherited;
end;

procedure TWorkThread.Execute;
begin
  try
    while not Terminated and not FCanceled and Assigned(Self.FSender) do
    begin
      if WaitForSingleObject(FInEvent, INFINITE) = WAIT_OBJECT_0 then
      begin
        if FSyncExecute then
          Synchronize(Trigger)
        else
          Trigger;
      end;
      if WaitForSingleObject(FEvent, FInterval) = WAIT_OBJECT_0 then
        Exit;
    end;
  except
  end;
end;

procedure TWorkThread.Start;
begin
  if not FEnabled then
  begin
    {$warnings off}
    if Suspended then
      Resume;
    {$warnings on}
    SetEvent(FInEvent);
    FEnabled := True;
  end;
end;

procedure TWorkThread.Stop;
begin
  if FEnabled then
  begin
    FEnabled := False;
    ResetEvent(FInEvent);
    SetEvent(FEvent);
  end;
end;

procedure TWorkThread.Terminate;
begin
  SetEvent(FEvent);
  SetEvent(FInEvent);
  FCanceled := True;
  inherited Terminate;
end;

procedure TWorkThread.Trigger;
begin
  if Assigned(FNEvent) and not FCanceled and not Terminated then
    FNEvent(FSender);
end;

{ TMySFTPItems }

function TSFTPItems.Add: TSFTPItem;
begin
  Result := TSFTPItem( inherited Add);
end;

constructor TSFTPItems.Create(AOwner: TComponent);
begin
  inherited Create(TSFTPItem);
  FOwner := AOwner;
end;

function TSFTPItems.GetItems(const AIndex: Integer): TSFTPItem;
begin
  Result := TSFTPItem( inherited Items[AIndex]);
end;

function TSFTPItems.GetOwner: TPersistent;
begin
  Result := FOwner;
end;

function TSFTPItems.IndexOf(const AItem: TSFTPItem): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to Count - 1 do
    if AItem = Items[I] then
    begin
      Result := I;
      Exit;
    end;
end;

procedure TSFTPItems.ParseEntryBuffers(ABuffer, ALongEntry: PAnsiChar;
  const AAttributes: LIBSSH2_SFTP_ATTRIBUTES; ACodePage: Word);

const
  UID_POS = 3;
  GID_POS = 4;

  // surf the string to extract uid/gid name values
  // this was only tested on openssh server listing
  // hence the above constants for pos,
  // dunno if this is standardized or not
  function ExtractEntryData(ALongEntry: PAnsiChar; const APosition: Integer): string; inline;
  var
    I, J, L, K: Integer;
    S: string;
    P: PAnsiChar;
  begin
    Result := '';
    if ALongEntry = nil then
      Exit;
    J := APosition - 1;
    if J < 0 then
      J := 0;
    L := Length(ALongEntry);
    S := '';
    P := ALongEntry;
    K := 0;
    for I := 0 to L - 1 do
    begin
      if (P^ in [#9, #13, #32]) and ((P + sizeof(P^))^ <> #32) then
      begin
        Inc(P);
        Inc(K);
        Dec(J);
        if J = 0 then
        begin
          Inc(ALongEntry, I + K);
          K := I;
          for J := I to L - 1 do
          begin
            if P^ in [#0, #9, #13, #32] then
            begin
              K := J;
              break;
            end;
            Inc(P);
          end;
          SetString(S, ALongEntry, K - I);
          break;
        end
      end;
      Inc(P);
      if P^ = #0 then
        break;
    end;
    Result := S;
  end;

var
  Item: TSFTPItem;
  LinkAttrs: LIBSSH2_SFTP_ATTRIBUTES;
  Client: TSFTPClient;
begin
  if (ABuffer = nil) or (ABuffer = '.') or (ABuffer = '..') then
    Exit;

  Item := Add;
  Item.FileName := DecodeStr(ABuffer, ACodePage);
  if TestBit(AAttributes.Flags, LIBSSH2_SFTP_ATTR_PERMISSIONS) then
  begin
    case AAttributes.Permissions and LIBSSH2_SFTP_S_IFMT of
      LIBSSH2_SFTP_S_IFDIR:
        Item.ItemType := sitDirectory;
      LIBSSH2_SFTP_S_IFBLK:
        Item.ItemType := sitBlockDev;
      LIBSSH2_SFTP_S_IFIFO:
        Item.ItemType := sitFIFO;
      LIBSSH2_SFTP_S_IFCHR:
        Item.ItemType := sitCharDev;
      LIBSSH2_SFTP_S_IFSOCK:
        Item.ItemType := sitSocket;
      LIBSSH2_SFTP_S_IFLNK:
        begin
          if not(Owner is TSSH2Client) then
            Exit;
          Client := TSFTPClient(Owner);
          FillChar(LinkAttrs, sizeof(LinkAttrs), 0);
          try
            Item.LinkPath := Client.ResolveSymLink(Client.CurrentDirectory + '/' + Item.FFileName,
              LinkAttrs, True);
            if TestBit(LinkAttrs.Flags, LIBSSH2_SFTP_ATTR_PERMISSIONS) and
              (LinkAttrs.Permissions and LIBSSH2_SFTP_S_IFMT = LIBSSH2_SFTP_S_IFDIR) then
              Item.ItemType := sitSymbolicLinkDir
            else
              Item.ItemType := sitSymbolicLink;
            if TestBit(LinkAttrs.Flags, LIBSSH2_SFTP_ATTR_SIZE) then
              Item.LinkSize := LinkAttrs.FileSize
            else
              Item.LinkSize := 0;

          except
            on E: ESSH2Exception do
            begin
              Item.LinkPath := '';
              Item.LinkSize := 0;
              Item.ItemType := sitSymbolicLink;
            end;
          end;
        end;
      LIBSSH2_SFTP_S_IFREG:
        Item.ItemType := sitFile;
    end;
    Item.Permissions := AAttributes.Permissions;
  end
  else
  begin
    Item.ItemType := sitUnknown;
    Item.Permissions := 0;
  end;

  if TestBit(AAttributes.Flags, LIBSSH2_SFTP_ATTR_SIZE) then
    Item.FileSize := AAttributes.FileSize
  else
    Item.FileSize := 0;

  Item.Hidden := ABuffer[0] = '.';

  if TestBit(AAttributes.Flags, LIBSSH2_SFTP_ATTR_UIDGID) then
  begin
    Item.UID := AAttributes.UID;
    Item.GID := AAttributes.GID;
    Item.UIDStr := ExtractEntryData(ALongEntry, UID_POS);
    Item.GIDStr := ExtractEntryData(ALongEntry, GID_POS);
  end
  else
  begin
    Item.UID := 0;
    Item.GID := 0;
    Item.UIDStr := '';
    Item.GIDStr := '';
  end;

  if TestBit(AAttributes.Flags, LIBSSH2_SFTP_ATTR_ACMODTIME) then
  begin
    Item.LastAccessTime := UnixToDateTime(AAttributes.ATime);
    Item.LastModificationTime := UnixToDateTime(AAttributes.MTime);
  end
  else
  begin
    Item.LastAccessTime := 0;
    Item.LastModificationTime := 0;
  end;
end;

procedure TSFTPItems.SetItems(const AIndex: Integer; const Value: TSFTPItem);
begin
  inherited Items[AIndex] := Value;
end;

function StrCmpLogicalW(psz1, psz2: PWideChar): integer; stdcall;  external 'shlwapi.dll' name 'StrCmpLogicalW';

procedure TSFTPItems.SortDefault;
var
  T: TSFTPItem;

  function MyCmpWStr(const W1, W2: WideString): Integer; inline;
  begin
    //Result := WideCompareStr(W1, W2) //CompareStringW(LOCALE_INVARIANT, 0, PWideChar(W1), -1, PWideChar(W2), -1);
    if W1 > W2 then
      Result := 1
    else if W1 < W2 then
      Result := -1
    else
      Result := 0;
  end;

  procedure QuickSort(AItems: TSFTPItems; L, R: Integer);
  var
    I, J: Integer;
    P: TSFTPItem;
  begin
    repeat
      I := L;
      J := R;
      P := AItems[(L + R) shr 1]; // AItems[L + Trunc(Random(R - L + 1))];
      repeat
        repeat
          Inc(I);
        until not(MyCmpWStr(AItems[I - 1].FFileName, P.FFileName) < 0);
        Dec(I);
        repeat
          Dec(J);
        until not(MyCmpWStr(P.FFileName, AItems[J + 1].FFileName) < 0);
        Inc(J);

        if I > J then
          break;

        T.Assign(AItems[I]);
        AItems[I].Assign(AItems[J]);
        AItems[J].Assign(T);

        if P = AItems[I] then
          P := AItems[J]
        else if P = AItems[J] then
          P := AItems[I];

        Inc(I);
        Dec(J);
      until I > J;

      if L < J then
        QuickSort(AItems, L, J);
      L := I;
    until I >= R;
  end;

var
  Dirs, Files: TSFTPItems;
  I, K, L: Integer;
  Item, SItem: TSFTPItem;
begin
  //
  Dirs := TSFTPItems.Create(nil);
  Files := TSFTPItems.Create(nil);
  try
    for I := 0 to Count - 1 do
    begin
      Item := Items[I];
      if Item.ItemType in [sitDirectory, sitSymbolicLinkDir] then
      begin
        SItem := Dirs.Add;
        SItem.Assign(Item);
      end
      else
      begin
        SItem := Files.Add;
        SItem.Assign(Item);
      end;
    end;

    K := Dirs.Count;
    L := Files.Count;
    T := TSFTPItem.Create(nil);
    try
      if K > 1 then
        QuickSort(Dirs, 0, K - 1);
      if L > 1 then
        QuickSort(Files, 0, L - 1);
    finally
      T.Free;
    end;

    for I := 0 to K - 1 do
      Items[I].Assign(Dirs[I]);

    for I := 0 to L - 1 do
      Items[I + K].Assign(Files[I]);

  finally
    Dirs.Free;
    Files.Free;
  end;
end;

{ TSSH2Client }

procedure TSSH2Client.Cancel(ADisconnect: Boolean);
begin
  //
  FCanceled := True;
  Sleep(500);
  try
    if ADisconnect then
      Disconnect;
  except
  end;
end;

procedure TSSH2Client.Connect;
type
  PAbstractData = ^TAbstractData;

  TAbstractData = record
    SelfPtr: Pointer;
    Extra: Pointer;
    sPassword: AnsiString;
  end;

var
  ADebugMode: Boolean;
  R: Integer; // last call SSH state
  sError, sErrorFirst, sException: string; // cached last SSH Error

  procedure log(const S: string); inline;
  begin
    //--if ADebugMode then
    dbg('connect: ' + S); // optional!
  end;

  procedure CacheLastSSHError(R: Integer);
  begin
    if R <> 0 then
    begin
      sError := GetLastSSHError(R);
      if sErrorFirst = '' then sErrorFirst := sError;
    end;
  end;

  function HandleFingerprint(const AState: TFingerprintState; const F: Pointer): Boolean;
  var
    HashAction: TConnectHashAction;
  begin
    Result := False;
    HashAction := chaIgnore;
    if ADebugMode then log('DoOnFingerprint:'); //@dbg
    DoOnFingerprint(AState, HashAction);
    if ADebugMode then log('DoOnFingerprint.'); //@dbg
    case HashAction of
      chaIgnore:
        begin
          if ADebugMode then log('HashAction: chaIgnore'); //@dbg
        end;
      chaCancel:
        begin
          if ADebugMode then log('HashAction: chaCancel'); //@dbg
          Result := True;
        end;
      chaSave:
        begin
          if ADebugMode then log('HashAction: chaSave'); //@dbg
          if ADebugMode then log('HashMgr.StoreFingerprint:'); //@dbg
          FHashMgr.StoreFingerprint(FHost, FPort, F);
          if ADebugMode then log('HashMgr.StoreFingerprint.'); //@dbg
        end;
    end;
  end;

  function ParseAuthList(const AList: PAnsiChar): TAuthModes;
  var
    Modes: TAuthModes;
    S: string;
  begin
    S := string(AList);
    if amTryAll in FAuthModes then
    begin
      Result := [amTryAll]; // foreach all auth methods
      Exit;
    end;

    Modes := [];
    if Pos('password', S) > 0 then
    begin
      // when "FAuthModes == []" use only server allowed mode else server allowed and client supported!
      if (FAuthModes = []) or (amPassword in FAuthModes) then
        Modes := Modes + [amPassword];
    end;

    if Pos('publickey', S) > 0 then
    begin
      if (FAuthModes = []) or (amPublicKey in FAuthModes) then
        Modes := Modes + [amPublicKey];
      //?if Pos('agent', S) > 0 then
      begin
        if (FAuthModes = []) or (amPublicKeyViaAgent in FAuthModes) then
          Modes := Modes + [amPublicKeyViaAgent];
      end;
    end;
    if Pos('keyboard-interactive', S) > 0 then
    begin
      if (FAuthModes = []) or (amKeyboardInteractive in FAuthModes) then
        Modes := Modes + [amKeyboardInteractive];
    end;

    Result := Modes;

    if Result = [] then
      RaiseSSHError('Server does not support requested auth mode(s)');
  end;

  function UserAuthPassword(): Boolean;
  var
    sUserName, sPassword: AnsiString;
    pUserName, pPassword: PAnsiChar;
  begin
    //-if (FUserName = EmptyStr) then pUserName := nil else // !Not necessarily
    begin
      sUserName := AnsiString(FUserName);
      pUserName := PAnsiChar(sUserName);
    end;
    //-if (FPassword = EmptyStr) then pPassword := nil else // !Not necessarily
    begin
      sPassword := AnsiString(FPassword);
      pPassword := PAnsiChar(sPassword);
    end;
    if ADebugMode then log('libssh2_userauth_password:'); //@dbg
    try
      R := libssh2_userauth_password(FSession, pUserName, pPassword);
      if ADebugMode then log('libssh2_userauth_password. R: ' + IntToStr(R)); //@dbg
      Result := R = 0;
      if not Result then CacheLastSSHError(R);
      if (not Result) and ADebugMode then log('Failed auth: ' + sError); //@dbg
    except
      on e: Exception do
      begin
        //if FDebugMode then
        dbg('exception: ' + e.Message);
        if sException = '' then sException := e.Message;
        Result := False;
      end;
    end;
  end;

  procedure KbdInteractiveCallback(const Name: PAnsiChar; name_len: Integer;
    const instruction: PAnsiChar; instruction_len: Integer; num_prompts: Integer;
    const prompts: PLIBSSH2_USERAUTH_KBDINT_PROMPT;
    var responses: LIBSSH2_USERAUTH_KBDINT_RESPONSE;
      _abstract: Pointer); cdecl;
  var
    sPassword: string;
    Data: PAbstractData;
    SSH2Client: TSSH2Client;
  begin
    if ADebugMode then log('KbdInteractiveCallback: #' + IntToStr(num_prompts)); //@dbg
    if num_prompts = 1 then
    try
      // zato sto je abstract->void**
      if (_abstract = nil) then Exit;
      Data := PAbstractData(Pointer(_abstract)^);
      if (Data = nil) then Exit;

      SSH2Client := TSSH2Client(Data.SelfPtr);
      sPassword := SSH2Client.Password;
      // TODO -o##jpluimers -cGeneral : if Password is assigned, then firs try that at least once before asking
      if Assigned(SSH2Client.FOnKeybInt) then
      begin
        if ADebugMode then log('SSH2Client.OnKeybInt:'); //@dbg
        SSH2Client.FOnKeybInt(Data.SelfPtr, sPassword);
        if ADebugMode then log('SSH2Client.OnKeybInt.'); //@dbg
      end;

      if (sPassword <> '') and (Pos('password', LowerCase(string(prompts.Text))) > 0) then
      begin
        Data.sPassword := AnsiString(sPassword);
        responses.text := PAnsiChar(Data.sPassword);
        responses.length := Length(Data.sPassword);
      end;
    except
      on e: Exception do
      begin
        //if FDebugMode then
        dbg('exception: ' + e.Message);
      end;
    end; // if num_prompts = 1 then
    if ADebugMode then log('KbdInteractiveCallback.'); //@dbg
  end;

  function UserAuthKeyboardInteractive(): Boolean;
  var
    sUserName: AnsiString;
    pUserName: PAnsiChar;
  begin
    //-if (FUserName = EmptyStr) then pUserName := nil else // !Not necessarily
    begin
      sUserName := AnsiString(FUserName);
      pUserName := PAnsiChar(sUserName);
    end;
    if ADebugMode then log('libssh2_userauth_keyboard_interactive:'); //@dbg
    try
      R := libssh2_userauth_keyboard_interactive(FSession, pUserName, @KbdInteractiveCallback);
      if ADebugMode then log('libssh2_userauth_keyboard_interactive. R: ' + IntToStr(R)); //@dbg
      Result := R = 0;
      if not Result then CacheLastSSHError(R);
      if (not Result) and ADebugMode then log('Failed auth: ' + sError); //@dbg
    except
      on e: Exception do
      begin
        //if FDebugMode then
        dbg('exception: ' + e.Message);
        if sException = '' then sException := e.Message;
        Result := False;
      end;
    end;
  end;

  function UserAuthPKey(Forcibly: Boolean = False): Boolean;
  //{$REGION 'History'}
  //  19-Sep-2019 - Failed While connecting with a Private Key only
  //                missing paramters must be Nil not EmptyStr
  //{$ENDREGION}
  var
    sUserName, sPubKeyPath, sPrivKeyPath, sPrivKeyPass: AnsiString;
    pUserName, pPubKeyPath, pPrivKeyPath, pPrivKeyPass: PAnsiChar;
  begin
    if (not Forcibly) and (FPubKeyPath = EmptyStr) and (FPrivKeyPath = EmptyStr) then
    begin
      if ADebugMode then log('Failed defined any key file!');
      if sError = '' then
        sError := 'Failed defined any key file';
      Result := False;
      Exit;
    end;
    //-if (FUserName = EmptyStr) then pUserName := nil else // !Not necessarily
    begin
      sUserName := AnsiString(FUserName);
      pUserName := PAnsiChar(sUserName);
    end;
    if (FPubKeyPath = EmptyStr) then pPubKeyPath := nil else //!!! PubKeyPath allowed nil
    begin
      sPubKeyPath := AnsiString(FPubKeyPath);
      pPubKeyPath := PAnsiChar(sPubKeyPath);
    end;
    //--if (FPrivKeyPath = EmptyStr) then pPrivKeyPath := nil else // AV when == nil
    begin
      sPrivKeyPath := AnsiString(FPrivKeyPath);
      pPrivKeyPath := PAnsiChar(sPrivKeyPath);
    end;
    if (FPrivKeyPass = EmptyStr) then pPrivKeyPass := nil else // !Not necessarily
    begin
      sPrivKeyPass := AnsiString(FPrivKeyPass);
      pPrivKeyPass := PAnsiChar(sPrivKeyPass);
    end;
    if ADebugMode then log('libssh2_userauth_publickey_fromfile:'); //@dbg
    try
      R := libssh2_userauth_publickey_fromfile_ex(FSession,
        pUserName, Length(sUserName), pPubKeyPath, pPrivKeyPath, pPrivKeyPass);
      if ADebugMode then log('libssh2_userauth_publickey_fromfile. R: ' + IntToStr(R)); //@dbg
      Result := R = 0;
      if not Result then CacheLastSSHError(R);
      if (not Result) and ADebugMode then log('Failed auth: ' + sError); //@dbg
    except
      on e: Exception do
      begin
        //if FDebugMode then
        dbg('exception: ' + e.Message);
        if sException = '' then sException := e.Message;
        Result := False;
      end;
    end;
  end;

  function UserAuthPKeyViaAgent(): Boolean;
  var
    Agent: PLIBSSH2_AGENT;
    Identity, PrevIdentity: PLIBSSH2_AGENT_PUBLICKEY;
    sUserName: AnsiString;
    pUserName: PAnsiChar;
  begin
    Result := False;
    if ADebugMode then log('libssh2_agent_init:'); //@dbg
    try
      Agent := libssh2_agent_init(FSession);
      if ADebugMode then log('libssh2_agent_init.'); //@dbg
      if Agent <> nil then
      begin
        try
          if ADebugMode then log('libssh2_agent_connect:'); //@dbg
          R := libssh2_agent_connect(Agent);
          if ADebugMode then log('libssh2_agent_connect. R: ' + IntToStr(R)); //@dbg
          if R <> 0 then CacheLastSSHError(R);
          if (R <> 0) and ADebugMode then log('Failed agent connect: ' + sError); //@dbg
          if R = 0 then
          begin
            if ADebugMode then log('libssh2_agent_list_identities:'); //@dbg
            R := libssh2_agent_list_identities(Agent);
            if ADebugMode then log('libssh2_agent_list_identities. R: ' + IntToStr(R)); //@dbg
            if R <> 0 then CacheLastSSHError(R);
            if (R <> 0) and ADebugMode then log('Failed agent identities: ' + sError); //@dbg
            if R = 0 then
            begin
              PrevIdentity := nil;
              while True do
              begin
                if ADebugMode then log('libssh2_agent_get_identity:'); //@dbg
                R := libssh2_agent_get_identity(Agent, Identity, PrevIdentity);
                if ADebugMode then log('libssh2_agent_get_identity. R: ' + IntToStr(R)); //@dbg
                if R <> 0 then CacheLastSSHError(R);
                if (R <> 0) and ADebugMode then log('Failed agent identity: ' + sError); //@dbg
                if R <> 0 then
                  break;
                if ADebugMode then log('libssh2_agent_userauth:'); //@dbg
                //if (FUserName = EmptyStr) then pUserName := nil else // ?!Not necessarily
                begin
                  sUserName := AnsiString(FUserName);
                  pUserName := PAnsiChar(sUserName);
                end;
                R := libssh2_agent_userauth(Agent, pUserName, Identity);
                if ADebugMode then log('libssh2_agent_userauth. R: ' + IntToStr(R)); //@dbg
                if R <> 0 then CacheLastSSHError(R);
                if (R <> 0) and ADebugMode then log('Failed agent userauth: ' + sError); //@dbg
                if R = 0 then
                begin
                  Result := True;
                  break;
                end;
                PrevIdentity := Identity;
              end;
            end;
            if ADebugMode then log('libssh2_agent_disconnect:'); //@dbg
            libssh2_agent_disconnect(Agent);
            if ADebugMode then log('libssh2_agent_disconnect.'); //@dbg
          end;
        finally
          if ADebugMode then log('libssh2_agent_free:'); //@dbg
          libssh2_agent_free(Agent);
          if ADebugMode then log('libssh2_agent_free.'); //@dbg
        end;
      end;
    except
      on e: Exception do
      begin
        //if FDebugMode then
        dbg('exception: ' + e.Message);
        if sException = '' then sException := e.Message;
      end;
    end;
  end;

  function UserAuthTryAll(): Boolean;
  var
    IsKeyFiles, IsPassword: Boolean;
  begin
    IsKeyFiles := (FPubKeyPath <> '') or (FPrivKeyPath <> '');

    if IsKeyFiles then
    begin
      Result := UserAuthPKey();
      if Result then Exit;
      Result := UserAuthPKeyViaAgent();
      if Result then Exit;
    end;

    IsPassword := FPassword <> '';
    if IsPassword then
    begin
      Result := UserAuthPassword();
      if Result then Exit;
    end;

    Result := UserAuthKeyboardInteractive();
    if Result then Exit;
    if not (IsKeyFiles or IsPassword) then
    begin
      sErrorFirst := '';
      sException := '';
    end;

    if not IsKeyFiles then
    begin
      Result := UserAuthPKey({Forcibly:}True);
      if Result then Exit;
      Result := UserAuthPKeyViaAgent();
      if Result then Exit;
      if not IsPassword then
      begin
        sErrorFirst := '';
        sException := '';
      end;
    end;

    if not IsPassword then
      Result := UserAuthPassword();

    //Result := UserAuthPassword()
    //  or UserAuthKeyboardInteractive()
    //  or UserAuthPKey()
    //  or UserAuthPKeyViaAgent();
  end;

var
  Sock, iRepeat, iRepeatLimit: Integer;
  Fingerprint{, StoredFingerprint}: array of Byte;
  StoredFingerprint: Pointer;
  Abstract: TAbstractData;
  Aborted: Boolean;
  UserAuthList: PAnsiChar;
  AuthMode: TAuthModes;
  OK, AuthOK: Boolean;
  Prefs: AnsiString;
  HashMode: THashMode;
label
  L_AUTH_REPEAT;
begin
  if Connected then
    Exit;
  ADebugMode := fDebugMode;
  if ADebugMode then log('Start:'); // @dbg

  R := 0;
  FCanceled := False;
  if ADebugMode then log('CreateSocket:'); // @dbg
  Sock := CreateSocket;
  if ADebugMode then log('CreateSocket.'); // @dbg
  if Sock = INVALID_SOCKET then
    Exit;
  if ADebugMode then log('ConnectSocket:'); // @dbg
  OK := ConnectSocket(Sock);
  if ADebugMode then log('ConnectSocket.'); // @dbg
  if not OK then
    RaiseSSHError(FLastErrStr);
  FSocket := Sock;
  if FSession <> nil then
  begin
    if ADebugMode then log('libssh2_session_free:'); // @dbg
    libssh2_session_free(FSession);
    FSession := nil;
    if ADebugMode then log('libssh2_session_free.'); // @dbg
  end;

  Abstract.SelfPtr := Self;
  Abstract.Extra := nil;
  if ADebugMode then log('libssh2_session_init_ex:'); // @dbg
  FSession := libssh2_session_init_ex(nil, nil, nil, @Abstract);
  if ADebugMode then log('libssh2_session_init_ex.'); // @dbg
  if FSession = nil then
    RaiseSSHError;

  {+} // https://www.libssh2.org/examples/sftp.html
  // Since we have set non-blocking, tell libssh2 we are blocking
  //if ADebugMode then log('libssh2_session_set_blocking:'); //@dbg
  //???libssh2_session_set_blocking(FSession, 1);
  //if ADebugMode then log('libssh2_session_set_blocking.'); //@dbg

  // ... start it up. This will trade welcome banners, exchange keys,
  // and setup crypto, compression, and MAC layers
  //if ADebugMode then log('libssh2_session_handshake:'); //@dbg
  //???R := libssh2_session_handshake(FSession, FSocket);
  //if ADebugMode then log('libssh2_session_handshake.'); //@dbg
  //if R <> 0 then
  //begin
  //  Disconnect;
  //  RaiseSSHError('Failure establishing SSH session: ' + IntToStr(R));
  //end;
  {+.}

  if ADebugMode then log('libssh2_banner_set:'); // @dbg
  libssh2_banner_set(FSession, PAnsiChar(MyEncode(FClientBanner)));
  if ADebugMode then log('libssh2_banner_set.'); // @dbg

  if FCompression then
  begin
    if ADebugMode then log('libssh2_session_flag: LIBSSH2_FLAG_COMPRESS'); // @dbg
    libssh2_session_flag(FSession, LIBSSH2_FLAG_COMPRESS, 1);
    if ADebugMode then log('libssh2_session_flag.'); // @dbg

    Prefs := 'zlib,none';

    if ADebugMode then log('libssh2_session_method_pref: COMP_CS'); // @dbg
    R := libssh2_session_method_pref(FSession, LIBSSH2_METHOD_COMP_CS, PAnsiChar(AnsiString(Prefs)));
    if ADebugMode then log('libssh2_session_method_pref.'); // @dbg
    if R <> 0 then CacheLastSSHError(R);
    if R <> 0 then
      if ADebugMode then log('Error setting comp_cs: ' + sError);

    if ADebugMode then log('libssh2_session_method_pref: COMP_SC'); // @dbg
    R := libssh2_session_method_pref(FSession, LIBSSH2_METHOD_COMP_SC, PAnsiChar(AnsiString(Prefs)));
    if ADebugMode then log('libssh2_session_method_pref.'); // @dbg
    if R <> 0 then CacheLastSSHError(R);
    if (R <> 0) and ADebugMode then log('Error setting comp_sc: ' + sError);
  end;

  if ADebugMode then log('libssh2_session_startup:'); // @dbg
  R := libssh2_session_startup(FSession, FSocket);
  if ADebugMode then log('libssh2_session_startup.'); // @dbg
  if R = 0 then
  begin
    if Assigned(FHashMgr) then
    begin
      if ADebugMode then log('HashMgr.GetHashMode:'); // @dbg
      HashMode := FHashMgr.GetHashMode;
      if ADebugMode then log('HashMgr.GetHashMode.'); // @dbg
      if ADebugMode then log('HashMode: '+IntToStr(Integer(HashMode))); // @dbg
      case HashMode of
        hmMD5:
          begin
            SetLength(Fingerprint, MD5_DIGEST_LENGTH);
            if ADebugMode then log('libssh2_hostkey_hash: MD5'); // @dbg
            Pointer(Fingerprint) := libssh2_hostkey_hash(FSession, LIBSSH2_HOSTKEY_HASH_MD5);
            if ADebugMode then log('libssh2_hostkey_hash.'); // @dbg
          end;
        hmSHA1:
          begin
            SetLength(Fingerprint, SHA_DIGEST_LENGTH);
            if ADebugMode then log('libssh2_hostkey_hash: SHA1'); // @dbg
            Pointer(Fingerprint) := libssh2_hostkey_hash(FSession, LIBSSH2_HOSTKEY_HASH_SHA1);
            if ADebugMode then log('libssh2_hostkey_hash.'); // @dbg
          end;
      end;
      Aborted := False;
      if ADebugMode then log('HashMgr.GetFingerprint:'); // @dbg
      {Pointer(StoredFingerprint)}StoredFingerprint := FHashMgr.GetFingerprint(FHost, FPort);
      if ADebugMode then log('HashMgr.GetFingerprint.'); // @dbg
      if StoredFingerprint = nil then
      begin
        if ADebugMode then log('HandleFingerprint:'); // @dbg
        Aborted := HandleFingerprint(fsNew, Fingerprint);
        if ADebugMode then log('HandleFingerprint.'); // @dbg
      end
      else begin
        if ADebugMode then log('HashMgr.CompareFingerprints:'); // @dbg
        OK := FHashMgr.CompareFingerprints(Fingerprint, StoredFingerprint);
        if ADebugMode then log('HashMgr.CompareFingerprints.'); // @dbg
        if not OK then
        begin
          if ADebugMode then log('HandleFingerprint:'); // @dbg
          Aborted := HandleFingerprint(fsChanged, Fingerprint);
          if ADebugMode then log('HandleFingerprint.'); // @dbg
        end;
      end;

      if Aborted then
      begin
        if ADebugMode then log('Aborted!'); // @dbg
        Disconnect;
        Exit;
      end;
    end;

    if ADebugMode then log('libssh2_session_set_blocking:'); //@dbg
    libssh2_session_set_blocking(FSession, 1);
    if ADebugMode then log('libssh2_session_set_blocking.'); //@dbg

    if (FTimeOut > 0) and (FTimeOut<10) then FTimeOut := 10;
    if FKeepAlive then
    begin
      if ADebugMode then log('libssh2_keepalive_config: seconds: ' + IntToStr(FTimeOut)); // @dbg
      libssh2_keepalive_config(FSession, Integer(FKeepAlive), FTimeOut); // FTimeOut - number of seconds
      if ADebugMode then log('libssh2_keepalive_config.'); // @dbg
    end;

    if ADebugMode then log('libssh2_userauth_list:'); // @dbg
    UserAuthList := libssh2_userauth_list(FSession, PAnsiChar(AnsiString(FUserName)),
      Length(AnsiString(FUserName)));
    if ADebugMode then log('libssh2_userauth_list.'); // @dbg

    // added supports authentication method NONE: https://www.libssh2.org/libssh2_userauth_list.html
    if ADebugMode then log('libssh2_userauth_authenticated:'); // @dbg
    OK := libssh2_userauth_authenticated(FSession) > 0;
    if ADebugMode then log('libssh2_userauth_authenticated.'); // @dbg
    if not OK then
    begin // when not auth NONE
      OK := Assigned(UserAuthList);
      if not OK then
      begin
        Disconnect;
        RaiseSSHError('Could not get user auth list.');
      end;

      iRepeat := 0;
      iRepeatLimit := 17;
      sError := ''; sErrorFirst := ''; sException := '';
    L_AUTH_REPEAT :
      if iRepeat >= iRepeatLimit then
      begin
        if sErrorFirst <> '' then sError := sErrorFirst;
        if sError = '' then
        begin
          if (R <> 0) and Assigned(FSession) then
            sError := GetLastSSHError(R)
          else if sException <> '' then
            sError := sException
          else
            sError := 'Auth repeat limitation.';
        end;
        Disconnect;
        RaiseSSHError(sError);
      end;
      if (iRepeat > 0) and (sErrorFirst = '') and (sError <> '') then sErrorFirst := sError;
      Inc(iRepeat);

      AuthOK := False;
      if ADebugMode then log('ParseAuthList: "' + string(StrPas(UserAuthList)) + '"'); // @dbg
      AuthMode := ParseAuthList(UserAuthList);
      if ADebugMode then log('ParseAuthList.'); // @dbg
      if amTryAll in AuthMode then
      begin
        if ADebugMode then log('UserAuthTryAll:'); // @dbg
        AuthOK := UserAuthTryAll();
        if ADebugMode then log('UserAuthTryAll.'); // @dbg
      end
      else
      begin
        if (not AuthOK) and (amPublicKey in AuthMode)
          and ((FPubKeyPath <> '') or (FPrivKeyPath <> '')) then
        begin
          if ADebugMode then log('UserAuthPKey:'); // @dbg
          AuthOK := UserAuthPKey();
          if ADebugMode then log('UserAuthPKey.'); // @dbg
        end;

        if (not AuthOK) and (amPassword in AuthMode)
          and (FPassword <> '') then
        begin
          if ADebugMode then log('UserAuthPassword:'); // @dbg
          AuthOK := UserAuthPassword();
          if ADebugMode then log('UserAuthPassword.'); // @dbg
        end;

        if not AuthOK and (amKeyboardInteractive in AuthMode) then
        begin
          if ADebugMode then log('UserAuthKeyboardInteractive:'); // @dbg
          AuthOK := UserAuthKeyboardInteractive();
          if ADebugMode then log('UserAuthKeyboardInteractive.'); // @dbg
        end;

        if not AuthOK and (amPublicKeyViaAgent in AuthMode) then
        begin
          if ADebugMode then log('UserAuthPKeyViaAgent:'); // @dbg
          AuthOK := UserAuthPKeyViaAgent();
          if ADebugMode then log('UserAuthPKeyViaAgent.'); // @dbg
        end;
      end;

      OK := AuthOK;
      if (not OK) and ADebugMode then log('Auth Failed!'); // @dbg
      if OK then
      begin
        if ADebugMode then log('libssh2_userauth_authenticated:'); // @dbg
        R := libssh2_userauth_authenticated(FSession);
        if ADebugMode then log('libssh2_userauth_authenticated.'); // @dbg
        OK := R > 0;
        if (not OK) and ADebugMode then log('AuthFailed: ' + IntToStr(R)); //@dbg
      end;
      if not OK then
      begin
        OK := True; // repeat auth
        if Assigned(FOnAuthFail) then
        begin
          if ADebugMode then log('OnAuthFailed:'); // @dbg
          FOnAuthFail(Self, OK);
          if ADebugMode then log('OnAuthFailed.'); // @dbg
        end;
        if not OK then
        begin
          if ADebugMode then log('Abort Auth!'); // @dbg
          if sErrorFirst <> '' then sError := sErrorFirst;
          if sError = '' then
          begin
            if (R <> 0) and Assigned(FSession) then
              sError := GetLastSSHError(R)
            else if sException <> '' then
              sError := sException
            else
              sError := 'Abort Auth.';
          end;
          Disconnect;
          RaiseSSHError(sError);
          //Exit;
        end
        else
        begin
          if ADebugMode then log('Repeat Auth:'); // @dbg
          goto L_AUTH_REPEAT;
        end;
      end;
    end; // "if not OK" -  when not auth NONE

    if ADebugMode then log('Try Connected!'); // @dbg
    FConnected := True;
    if Assigned(FOnConnect) then
    begin
      if ADebugMode then log('OnConnect:'); // @dbg
      FOnConnect(Self);
      if ADebugMode then log('OnConnect.'); // @dbg
    end;
  end
  else
  begin
    if ADebugMode then log('Failed Auth!'); // @dbg
    RaiseSSHError;
  end;

  if ADebugMode then log('Done!'); // @dbg
end;

function TSSH2Client.ConnectSocket(var S: Integer): Boolean;
type
  PConectData = ^TConectData;

  TConectData = record
    S: Integer;
    ConnectRes: Integer;
    LastErr: string;
    ResAddrInfo: PAddrInfo;
    HaveRes: Boolean;
  end;

  procedure TryConnect(ASender: TObject);
  var
    PData: PConectData;
    P: PAddrInfo;
  begin
    //
    PData := PConectData(TWorkThread(ASender).Data);
    P := PData.ResAddrInfo;
    while P <> nil do
    begin
      PData.ConnectRes := connect2(PData.S, P^.ai_addr, P^.ai_addrlen);
      PData.LastErr := SysErrorMessage(WSAGetLastError);
      if PData.ConnectRes <> -1 then
        break;
      P := P^.ai_next;
    end;
    if PData.ConnectRes = -1 then
      WSACleanup;
    PData.HaveRes := True;
  end;

var
  Worker: TWorkThread;
  Data: TConectData;
  Hints: addrinfo;
  IpFamily: Integer;
  E: TMethod;
begin
  Result := False;
  if S <> INVALID_SOCKET then
  begin
    Data.HaveRes := False;
    Data.ConnectRes := -1;
    Data.S := S;

    IpFamily := Ord(FIPVersion);
    if IpFamily <> AF_UNSPEC then
    begin
      IpFamily := Ord(FIPVersion);
    end;

    FillChar(Hints, sizeof(Hints), 0);
    Hints.ai_family := IpFamily;
    Hints.ai_socktype := SOCK_STREAM;
    Hints.ai_protocol := IPPROTO_TCP;

    if getaddrinfo(PAnsiChar(AnsiString(FHost)), PAnsiChar(AnsiString(IntToStr(FPort))), @Hints,
      Data.ResAddrInfo) <> 0 then
      RaiseSSHError(SysErrorMessage(WSAGetLastError));

    Worker := TWorkThread.Create(True);
    try
      Worker.SyncExecute := False;
      Worker.ThreadSender := Worker;
      E.Code := @TryConnect;
      E.Data := Worker;
      Worker.Event := TNotifyEvent(E);
      Worker.Data := @Data;
      Worker.Start;
      while not(Data.HaveRes or FCanceled or Application.Terminated) do
      begin
        ProcessMsgs;
        Sleep(1);
      end;
      Worker.Stop;
      FLastErrStr := Data.LastErr;
      if not Worker.Terminated then
      begin
        Worker.Terminate;
        if FCanceled then
          TerminateThread(Worker.Handle, 0); // hiyoooo!!
      end;
    finally
      Worker.Free;
      freeaddrinfo(Data.ResAddrInfo);
    end;
    if not FCanceled then
      Result := Data.ConnectRes <> -1;
  end;
end;

constructor TSSH2Client.Create(AOwner: TComponent);
begin
  inherited;
  {$IFDEF DEUBUG}     //@dbg
  FDebugMode := True; //@dbg
  {$ENDIF}            //@dbg
  FHost := '';
  FPort := 22;
  FUserName := '';
  FPassword := '';
  FIPVersion := IPvUNSPEC;
  FAuthModes := [amTryAll];
  FClientBanner := LIBSSH2_SSH_BANNER;
  FConnected := False;
  FCanceled := False;
  FKeepAlive := False;
  FTimeOut := 10;
  FSockBufLen := 8 * 1024;
  FSocket := INVALID_SOCKET;
  FCodePage := CP_UTF8;
  FCompression := False;
  if InterlockedIncrement(GSSH2Init) = 1 then
    if libssh2_init(0) <> 0 then
      RaiseSSHError('Error initializing libssh2.');
end;

function TSSH2Client.CreateSocket: Integer;
var
  WSData: TWSAData;
begin
  Result := INVALID_SOCKET;
  if WSAStartup(MakeWord(2, 2), WSData) <> 0 then
  begin
    RaiseSSHError('Invalid winsock version!');
    Exit;
  end;
  Result := socket(Ord(FIPVersion), SOCK_STREAM, IPPROTO_TCP);
  if Result = INVALID_SOCKET then
  begin
    RaiseSSHError(SysErrorMessage(WSAGetLastError));
    Exit;
  end;

  setsockopt(Result, SOL_SOCKET, SO_SNDBUF, @FSockBufLen, sizeof(FSockBufLen));
  setsockopt(Result, SOL_SOCKET, SO_RCVBUF, @FSockBufLen, sizeof(FSockBufLen));
  setsockopt(Result, SOL_SOCKET, SO_KEEPALIVE, @FKeepAlive, sizeof(FKeepAlive));
end;

destructor TSSH2Client.Destroy;
begin
  if Connected then
    Disconnect;
  if InterlockedDecrement(GSSH2Init) < 1 then
    libssh2_exit;
  inherited;
end;

procedure TSSH2Client.Disconnect;
begin
  try
    if FSession <> nil then
    begin
      try
        libssh2_session_disconnect(FSession,
          PAnsiChar(AnsiString(FClientBanner + ': ' + GetVersion + ' going to shutdown. Bye.')));
      finally
        libssh2_session_free(FSession);
      end;
    end;
  finally
    closesocket(FSocket);
    FSocket := INVALID_SOCKET;
    FSession := nil;
    WSACleanup;
    FConnected := False;
  end;
end;

procedure TSSH2Client.DoOnFingerprint(const AState: TFingerprintState;
  var AAction: TConnectHashAction);
begin
  if Assigned(FOnFingerprint) then
    FOnFingerprint(Self, AState, AAction);
end;

function TSSH2Client.GetConnected: Boolean;
{ var
  Buf: Pointer; }
begin
  Result := False;
  if (FSession = nil) or { (FSFtp = nil) or } (FSocket = INVALID_SOCKET) then
    Exit;
  { if WinSock.send(FSocket, Buf, 0, 0) = SOCKET_ERROR then
    Exit; }
  Result := FConnected;
end;

function TSSH2Client.GetLastSSHError(E: Integer): string;
var
  I: Integer;
  P: PAnsiChar;
begin
  if E = 0 then
    Result := SysErrorMessage(WSAGetLastError)
  else
    Result := 'No error';
  I := 0;
  P := PAnsiChar(AnsiString(Result));
  if FSession <> nil then
    libssh2_session_last_error(FSession, P, I, 0);
  Result := string(P);
end;

function TSSH2Client.GetLibString: string;
begin
  Result := string(libssh2_version(0));
end;

function TSSH2Client.GetSessionMethodsStr: string;
begin
  Result := '';
  if FSession <> nil then
    Result := Format('KEX: %s, CRYPT: %s, MAC: %s, COMP: %s, LANG: %s',
      [libssh2_session_methods(FSession, LIBSSH2_METHOD_KEX), libssh2_session_methods(FSession,
        LIBSSH2_METHOD_CRYPT_CS), libssh2_session_methods(FSession, LIBSSH2_METHOD_MAC_CS),
      libssh2_session_methods(FSession, LIBSSH2_METHOD_COMP_CS) + ' ' +
      libssh2_session_methods(FSession, LIBSSH2_METHOD_COMP_SC),
      libssh2_session_methods(FSession, LIBSSH2_METHOD_LANG_CS)]);
end;

function TSSH2Client.GetSessionPtr: PLIBSSH2_SESSION;
begin
  Result := FSession;
end;

function TSSH2Client.GetSocketHandle: Integer;
begin
  Result := FSocket;
end;

function TSSH2Client.GetVersion: string;
begin
  Result := ClassName + ' v' + SFTPCLIENT_VERSION;
end;

function TSSH2Client.MyDecode(const S: AnsiString): WideString;
begin
  Result := DecodeStr(S, FCodePage);
end;

function TSSH2Client.MyEncode(const WS: WideString): AnsiString;
begin
  Result := EncodeStr(WS, FCodePage);
end;

procedure TSSH2Client.RaiseSSHError(const AMsg: string; E: Integer);
var
  sError: string;
begin
  if AMsg <> '' then
    sError := AMsg
  else
    sError := GetLastSSHError(E);
  //if FDebugMode then
  dbg('SSH ERROR: ' + sError); // @dbg
  raise ESSH2Exception.Create(sError)
end;

procedure TSSH2Client.SetAuthModes(const Value: TAuthModes);
begin
  if FAuthModes <> Value then
  begin
    //if Value = [] then // when == [] - use only server allowed
    //  Exit;
    if amTryAll in Value then
    begin
      FAuthModes := [amTryAll]; // foreach all methods
    end
    else
    begin
      FAuthModes := Value - [amTryAll]; // use only server allowed and client defined
    end;
  end;
end;

procedure TSSH2Client.SetConnected(const Value: Boolean);
begin
  if FConnected <> Value then
  begin
    FConnected := Value;
    if Value then
      Connect
    else
      Disconnect;
  end;
end;

{ TSFTPClient }

procedure TSFTPClient.Cancel(ADisconnect: Boolean);
begin
  //
  FCanceled := True;
  inherited;
end;

function TSFTPClient.ChangeDir(const APath: WideString): Boolean;
var
  DirHandle: PLIBSSH2_SFTP_HANDLE;
begin
  Result := False;
  if FSFtp <> nil then
  begin
    DirHandle := libssh2_sftp_opendir(FSFtp, PAnsiChar(MyEncode(APath)));
    if DirHandle <> nil then
    begin
      libssh2_sftp_closedir(DirHandle);
      Result := True;
    end;
  end;
  FLastDirChangedOK := Result;
end;

function TSFTPClient.OpenDir(const APath: WideString; AutoMake: Boolean = False; MakeMode: Integer = 0): Boolean;
begin
  Result := FCurrentDir = APath;
  if not Result then
  begin
    Result := ChangeDir(APath);
    if not Result and AutoMake then
    begin
      MakeDir(APath, MakeMode, {Recurse:}True);
      Result := ChangeDir(APath);
    end;
    if Result then
    begin
      FCurrentDir := APath;
      FItems.Path := APath;
    end;
  end;
end;

procedure TSFTPClient.Connect(const ARemoteDir: WideString);
var
  Dir: WideString;
  B: Boolean;
begin
  inherited Connect;
  if not Connected then
    Exit;
  FSFtp := libssh2_sftp_init(GetSessionPtr);
  if FSFtp = nil then
  begin
    Disconnect;
    RaiseSSHError;
  end;

  Dir := ExpandCurrentDirPath;
  if Dir = '' then
  begin
    B := True;
    if Assigned(FOnNoStartDir) then
      FOnNoStartDir(Self, B);
    if not B then
    begin
      Disconnect;
      Exit;
    end;
  end;

  if ARemoteDir <> '.' then
    if ARemoteDir <> Dir then
    begin
      if ChangeDir(ARemoteDir) then
        Dir := ARemoteDir
      else
      begin
        B := True;
        if Assigned(FOnNoStartDir) then
          FOnNoStartDir(Self, B);
        if not B then
        begin
          Disconnect;
          Exit;
        end;
      end;
    end;
  {+}
  //CurrentDirectory := Dir;
  FCurrentDir := Dir;
  {+.}
end;

constructor TSFTPClient.Create(AOwner: TComponent);
begin
  inherited;
  FCurrentDir := '.';
  FItems := TSFTPItems.Create(Self);
  FItems.Path := '';
  FLastDirChangedOK := False;
  FReadBufLen := 32 * 1024;
  FWriteBufLen := 32 * 1024 - 1;
end;

procedure TSFTPClient.DeleteDir(const ADirName: WideString);
begin
  FCanceled := False;
  if libssh2_sftp_rmdir(FSFtp, PAnsiChar(MyEncode(ADirName))) <> 0 then
    RaiseSSHError;
end;

procedure TSFTPClient.DeleteFile(const AFileName: WideString);
begin
  FCanceled := False;
  if libssh2_sftp_unlink(FSFtp, PAnsiChar(MyEncode(AFileName))) <> 0 then
    RaiseSSHError;
end;

destructor TSFTPClient.Destroy;
begin
  FItems.Free;
  if Connected then
    Disconnect;
  inherited;
end;

procedure TSFTPClient.Disconnect;
begin
  try
    if FSFtp <> nil then
      libssh2_sftp_shutdown(FSFtp);
    inherited;
  finally
    FSFtp := nil;
  end;
end;

function TSFTPClient.ExpandCurrentDirPath: WideString;
const
  BUF_LEN = 4 * 1024;
var
  DirHandle: PLIBSSH2_SFTP_HANDLE;
  Buf: PAnsiChar;
begin
  Result := '';

  DirHandle := libssh2_sftp_opendir(FSFtp, '.');
  if DirHandle <> nil then
  begin
    GetMem(Buf, BUF_LEN);
    try
      libssh2_sftp_realpath(FSFtp, nil, Buf, BUF_LEN);
      libssh2_sftp_close(DirHandle);
      Result := MyDecode(Buf);
    finally
      FreeMem(Buf);
    end;
  end
  else
    RaiseSSHError;
end;

{+}
function TSFTPClient.Exists(const ASourceFileName: WideString): Boolean;
var
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
  FHandle: PLIBSSH2_SFTP_HANDLE;
begin
  Result := False;
  if libssh2_sftp_stat(FSFtp, PAnsiChar(MyEncode(ASourceFileName)), Attribs) = 0 then
  begin
    if not TestBit(Attribs.Flags, LIBSSH2_SFTP_ATTR_SIZE) then
      dbgw('TSFTPClient::Get >> No size attrib:' + ASourceFileName);

    FHandle := libssh2_sftp_open(FSFtp, PAnsiChar(MyEncode(ASourceFileName)), LIBSSH2_FXF_READ, 0);
    if FHandle = nil then
      Exit;
    libssh2_sftp_close(FHandle);
    Result := True;
  end;
end;
{+.}

procedure TSFTPClient.Get(const ASourceFileName: WideString; const ADest: TStream;
  AResume: Boolean);
var
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
  Transfered, Total: UInt64;
  FHandle: PLIBSSH2_SFTP_HANDLE;
  Buf: PAnsiChar;
  R, N: Integer;
begin
  //
  FCanceled := False;
  if libssh2_sftp_stat(FSFtp, PAnsiChar(MyEncode(ASourceFileName)), Attribs) = 0 then
  begin
    if not TestBit(Attribs.Flags, LIBSSH2_SFTP_ATTR_SIZE) then
      dbgw('TSFTPClient::Get >> No size attrib:' + ASourceFileName);

    FHandle := libssh2_sftp_open(FSFtp, PAnsiChar(MyEncode(ASourceFileName)), LIBSSH2_FXF_READ, 0);
    if FHandle = nil then
      RaiseSSHError;

    if AResume then
    begin
      Total := UInt64(Attribs.FileSize) - UInt64(ADest.Position);
      libssh2_sftp_seek64(FHandle, ADest.Position);
    end
    else
      Total := Attribs.FileSize;

    Transfered := 0;
    GetMem(Buf, FReadBufLen);
    try
      repeat
        R := libssh2_sftp_read(FHandle, Buf, FReadBufLen);
        if R > 0 then
        begin
          N := ADest.Write(Buf^, R);
          if N > 0 then
          begin
            Inc(Transfered, N);
            if Assigned(FOnTProgress) then
              FOnTProgress(Self, ASourceFileName, Transfered, Total);
          end;
        end
        else if R < 0 then
          RaiseSSHError;
      until (R = 0) or FCanceled;
    finally
      FreeMem(Buf);
      libssh2_sftp_close(FHandle);
    end;
  end
  else
    RaiseSSHError;
end;

function TSFTPClient.GetLastSSHError(E: Integer): string;
var
  S: string;
  C: Integer;
begin
  S := '';
  if FSFtp <> nil then
  begin
    S := 'SFTP: ';
    if E = 0 then
    begin
      C := libssh2_sftp_last_error(FSFtp);
      if C = 0 then
      begin
        Result := SysErrorMessage(WSAGetLastError);
        Exit;
      end;
    end
    else
      C := E;
    case C of
      LIBSSH2_FX_OK:
        S := S + 'No error';
      LIBSSH2_FX_EOF:
        S := S + 'End of file';
      LIBSSH2_FX_NO_SUCH_FILE:
        S := S + 'No such file';
      LIBSSH2_FX_PERMISSION_DENIED:
        S := S + 'Permission denied';
      LIBSSH2_FX_FAILURE:
        S := S + 'Failure';
      LIBSSH2_FX_BAD_MESSAGE:
        S := S + 'Bad messagge';
      LIBSSH2_FX_NO_CONNECTION:
        S := S + 'No connection';
      LIBSSH2_FX_CONNECTION_LOST:
        S := S + 'Connection lost';
      LIBSSH2_FX_OP_UNSUPPORTED:
        S := S + 'Operation unsupported';
      LIBSSH2_FX_INVALID_HANDLE:
        S := S + 'Invalid handle';
      LIBSSH2_FX_NO_SUCH_PATH:
        S := S + 'No such path';
      LIBSSH2_FX_FILE_ALREADY_EXISTS:
        S := S + 'File exists';
      LIBSSH2_FX_WRITE_PROTECT:
        S := S + 'Write protect';
      LIBSSH2_FX_NO_MEDIA:
        S := S + 'No media';
      LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM:
        S := S + 'No space on filesystem';
      LIBSSH2_FX_QUOTA_EXCEEDED:
        S := S + 'Quota exceeded';
      LIBSSH2_FX_UNKNOWN_PRINCIPAL:
        S := S + 'Unknown principal';
      LIBSSH2_FX_LOCK_CONFlICT:
        S := S + 'Lock conflict';
      LIBSSH2_FX_DIR_NOT_EMPTY:
        S := S + 'Directory not empty';
      LIBSSH2_FX_NOT_A_DIRECTORY:
        S := S + 'Not a directory';
      LIBSSH2_FX_INVALID_FILENAME:
        S := S + 'Invalid filename';
      LIBSSH2_FX_LINK_LOOP:
        S := S + 'Link loop'
      else
        S := S + 'Unknown error';
    end;
  end
  else
    S := inherited GetLastSSHError(E);

  Result := S;
end;

procedure TSFTPClient.List(const AStartPath: WideString);
const
  BUF_LEN = 4 * 1024;
var
  EntryBuffer: array [0 .. BUF_LEN - 1] of AnsiChar;
  LongEntry: array [0 .. BUF_LEN - 1] of AnsiChar;
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
  R: Integer;
  DirHandle: PLIBSSH2_SFTP_HANDLE;
begin
  if not Connected then
    Exit;
  FCanceled := False;
  if AStartPath <> '' then
    if AStartPath <> FCurrentDir then
      if not ChangeDir(AStartPath) then
        RaiseSSHError('Could not change to dir: ' + AStartPath + ' :: ' + GetLastSSHError)
      else
        FCurrentDir := AStartPath;

  DirHandle := libssh2_sftp_opendir(FSFtp, PAnsiChar(MyEncode(CurrentDirectory)));
  if DirHandle = nil then
    RaiseSSHError('Could not open dir: ' + GetLastSSHError);

  FItems.Clear;
  FItems.BeginUpdate;
  try
    repeat
      R := libssh2_sftp_readdir_ex(DirHandle, EntryBuffer, BUF_LEN, LongEntry, BUF_LEN, @Attribs);
      if (R <= 0) or FCanceled then
        break;
      FItems.ParseEntryBuffers(EntryBuffer, LongEntry, Attribs, FCodePage);
    until not True;
  finally
    FItems.EndUpdate;
    libssh2_sftp_closedir(DirHandle);
    FItems.Path := FCurrentDir;
  end;
end;

procedure TSFTPClient.MakeDir(const ADirName: WideString; AMode: Integer; ARecurse: Boolean);
var
  Dir: WideString;
begin
  FCanceled := False;
  Dir := ADirName;
  if (Dir = '') or (Dir = '.') or (Dir = '/') then
    Exit;

  Dir := WideStringReplace(Dir, '/', '\', [rfReplaceAll]);
  Dir := WideStringReplace(Dir, '\\', '\', [rfReplaceAll]);

  if (Dir = '\') or (Dir = '.\') then
    Exit;

  if Dir[Length(Dir)] = '\' then
    SetLength(Dir, Length(Dir)-1);

  DoMakeDir(Dir, AMode, ARecurse);
end;

procedure TSFTPClient.DoMakeDir(const LDir: WideString; AMode: Integer; ARecurse: Boolean);
var // LDir - direcrory delimiter ( PathDelim ) ( windows '\' )
  SDir: WideString; // sub dir
  RDir: WideString; // direcrory delimiter '/' ( sftp )
  Mode: Integer;
begin
  FCanceled := False;
  if (LDir = '') or (LDir = PathDelim) then
    Exit;

  if ARecurse then
  begin
    SDir := ExtractFileDir(LDir);
    if (SDir <> '') and (SDir <> '.') then
    begin
      if PathDelim <> '/' then
        RDir := WideStringReplace(SDir, PathDelim, '/', [rfReplaceAll])
      else
        RDir := SDir;
      if not ChangeDir( RDir ) then
        DoMakeDir(SDir, AMode, ARecurse);
    end;
  end;

  if AMode <> 0 then
    Mode := AMode
  else
    // mkdir with standard perms 0755
    Mode := LIBSSH2_SFTP_S_IRWXU or LIBSSH2_SFTP_S_IRGRP or LIBSSH2_SFTP_S_IXGRP or
      LIBSSH2_SFTP_S_IROTH or LIBSSH2_SFTP_S_IXOTH;

  if PathDelim <> '/' then
    RDir := WideStringReplace(LDir, PathDelim, '/', [rfReplaceAll])
  else
    RDir := LDir;
  if libssh2_sftp_mkdir(FSFtp, PAnsiChar(MyEncode(RDir)), Mode) <> 0 then
    RaiseSSHError;
end;

procedure TSFTPClient.MakeSymLink(const AOrigin, ADest: WideString);
begin
  FCanceled := False;
  if libssh2_sftp_symlink(FSFtp, PAnsiChar(MyEncode(ADest)), PAnsiChar(MyEncode(AOrigin))) <> 0 then
    RaiseSSHError;
end;

procedure TSFTPClient.Put(const ASource: TStream; const ADestFileName: WideString;
  AOverwrite: Boolean);
var
  R, N, K: Integer;
  Mode: Integer;
  FHandle: PLIBSSH2_SFTP_HANDLE;
  Buf, StartBuf: PAnsiChar;
  Transfered, Total: UInt64;
begin
  FCanceled := False;
  Mode := LIBSSH2_FXF_WRITE or LIBSSH2_FXF_CREAT;
  if AOverwrite then
    Mode := Mode or LIBSSH2_FXF_TRUNC
  else
    Mode := Mode or LIBSSH2_FXF_EXCL; // ensure call fails if file exists

  FHandle := libssh2_sftp_open(FSFtp, PAnsiChar(MyEncode(ADestFileName)), Mode,
    LIBSSH2_SFTP_S_IRUSR or LIBSSH2_SFTP_S_IWUSR or LIBSSH2_SFTP_S_IRGRP or
      LIBSSH2_SFTP_S_IROTH);
  if FHandle = nil then
    RaiseSSHError;

  GetMem(Buf, FWriteBufLen);
  StartBuf := Buf;
  Transfered := 0;
  Total := ASource.Size - ASource.Position;
  try
    repeat
      N := ASource.Read(Buf^, FWriteBufLen);
      if N > 0 then
      begin
        K := N;
        repeat
          R := libssh2_sftp_write(FHandle, Buf, K);
          if R < 0 then
            RaiseSSHError;
          Inc(Transfered, R);
          Inc(Buf, R);
          Dec(K, R);
          if Assigned(FOnTProgress) then
            FOnTProgress(Self, ADestFileName, Transfered, Total);
        until (K <= 0) or FCanceled;
        Buf := StartBuf;
      end;
    until (N <= 0) or FCanceled;
  finally
    FreeMem(StartBuf);
    libssh2_sftp_close(FHandle);
  end;
end;

procedure TSFTPClient.RaiseSSHError(const AMsg: string; E: Integer);
begin
  inherited;
  //
end;

procedure TSFTPClient.Rename(const AOldName, ANewName: WideString);
begin
  FCanceled := False;
  if libssh2_sftp_rename(FSFtp, PAnsiChar(MyEncode(AOldName)), PAnsiChar(MyEncode(ANewName)))
    <> 0 then
    RaiseSSHError;
end;

function TSFTPClient.ResolveSymLink(const AOrigin: WideString;
  var AAtributes: LIBSSH2_SFTP_ATTRIBUTES; ARealPath: Boolean): string;
const
  BUF_LEN = 4 * 1024;
var
  Target: array [0 .. BUF_LEN - 1] of AnsiChar;
  R: Integer;
begin
  FCanceled := False;
  Result := '';
  if not ARealPath then
    R := libssh2_sftp_readlink(FSFtp, PAnsiChar(MyEncode(AOrigin)), PAnsiChar(@Target), BUF_LEN)
  else
    R := libssh2_sftp_realpath(FSFtp, PAnsiChar(MyEncode(AOrigin)), PAnsiChar(@Target), BUF_LEN);

  if R > 0 then
  begin
    Result := MyDecode(Target);
    libssh2_sftp_stat(FSFtp, PAnsiChar(@Target), AAtributes);
  end
  else
    RaiseSSHError;
end;

procedure TSFTPClient.SetAttributes(const APath: WideString; AAtribs: LIBSSH2_SFTP_ATTRIBUTES);
begin
  FCanceled := False;
  if libssh2_sftp_setstat(FSFtp, PAnsiChar(MyEncode(APath)), AAtribs) <> 0 then
    RaiseSSHError;
end;

procedure TSFTPClient.SetCurrentDir(const Value: string);
begin
  if FCurrentDir <> Value then
    if ChangeDir(Value) then
    begin
      FCurrentDir := Value;
      FItems.Path := Value;
    end;
end;

procedure TSFTPClient.SetPermissions(const APath: WideString; const AOctalPerms: string);
begin
  SetPermissions(APath, FromOctal(AOctalPerms));
end;

procedure TSFTPClient.SetPermissions(const APath: WideString; APerms: Cardinal);
var
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
begin
  FillChar(Attribs, sizeof(Attribs), 0);
  Attribs.Flags := LIBSSH2_SFTP_ATTR_PERMISSIONS;
  Attribs.Permissions := APerms;
  SetAttributes(APath, Attribs);
end;

{ TSCPClient }

procedure TSCPClient.Cancel(ADisconnect: Boolean);
begin
  FCanceled := True;
  inherited;
end;

procedure TSCPClient.Get(const ASourceFileName: WideString; const ADest: TStream;
  var AStat: TStructStat);
const
  BUF_LEN = 24 * 1024 - 1;
var
  Channel: PLIBSSH2_CHANNEL;
  N, R, K: Integer;
  Buf: array [0 .. BUF_LEN - 1] of AnsiChar;
begin
  //
  FCanceled := False;
  Channel := libssh2_scp_recv(GetSessionPtr, PAnsiChar(MyEncode(ASourceFileName)), AStat);
  if Channel = nil then
    RaiseSSHError;
  try
    N := 0;
    K := BUF_LEN;
    while (N < AStat.st_size) and not FCanceled do
    begin
      if AStat.st_size - N < K then
        K := AStat.st_size - N;

      R := libssh2_channel_read(Channel, Buf, K);
      if K = R then
      begin
        ADest.Write(Buf, K);
        if Assigned(FOnTProgress) then
          FOnTProgress(Self, ASourceFileName, N, AStat.st_size);
      end
      else
        RaiseSSHError;
      Inc(N, R);
    end;
  finally
    libssh2_channel_free(Channel);
  end;
end;

procedure TSCPClient.Put(const ASource: TStream; const ADestFileName: WideString;
  AFileSize: UInt64; ATime, MTime: TDateTime; AMode: Integer);
const
  BUF_LEN = 8 * 1024 - 1;
var
  Channel: PLIBSSH2_CHANNEL;
  Mode: Integer;
  Buf, StartBuf: PAnsiChar;
  N, K, R: Integer;
  Transfered: UInt64;
begin
  //
  FCanceled := False;
  if AMode <> 0 then
    Mode := AMode
  else
    Mode := LIBSSH2_SFTP_S_IRUSR or LIBSSH2_SFTP_S_IWUSR or LIBSSH2_SFTP_S_IRGRP or
      LIBSSH2_SFTP_S_IROTH;
  Channel := libssh2_scp_send64(GetSessionPtr, PAnsiChar(MyEncode(ADestFileName)), Mode, AFileSize,
    DateTimeToUnix(ATime), DateTimeToUnix(MTime));
  if Channel = nil then
    RaiseSSHError;
  GetMem(Buf, BUF_LEN);
  StartBuf := Buf;
  Transfered := 0;
  try
    repeat
      N := ASource.Read(Buf^, BUF_LEN);
      if N > 0 then
      begin
        K := N;
        repeat
          R := libssh2_channel_write(Channel, Buf, K);
          if R < 0 then
            RaiseSSHError;
          Inc(Transfered, R);
          Inc(Buf, R);
          Dec(K, R);
          if Assigned(FOnTProgress) then
            FOnTProgress(Self, ADestFileName, Transfered, AFileSize);
        until (K <= 0) or FCanceled;
        Buf := StartBuf;
      end;
    until (N <= 0) or FCanceled;
    libssh2_channel_send_eof(Channel);
    libssh2_channel_wait_eof(Channel);
    libssh2_channel_wait_closed(Channel);
  finally
    FreeMem(Buf);
    libssh2_channel_free(Channel);
  end;
end;

initialization
  GSSH2Init := 0;
  {$if declared(uHVDll)}
  dll_ws2_32 := TDll.Create(dll_ws2_32_name, dll_ws2_32_entires);
  //dll_ws2_32.Load(); // @dbg
  {$ifend}
finalization
  {$if declared(uHVDll)}
  dll_ws2_32.Unload;
  {$ifend}
end.
