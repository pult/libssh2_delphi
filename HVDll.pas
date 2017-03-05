unit HVDll;
//
// https://github.com/pult/dll_load_delay
// https://bitbucket.org/VadimLV/dll_load_delay
// http://hallvards.blogspot.com/2008/03/tdm8-delayloading-of-dlls.html
//
// Support for DelayLoading of DLLs like VC++6.0 or latest Delphi (delayed)
// Written by Hallvard Vassbotn (hallvard@falcon.no), January 1999
//
interface

{$UNDEF SUPPORTED}
{$IFDEF WIN32}
  {$DEFINE SUPPORTED} // TODO: Check Delphi and FPC
{$ENDIF}
{$IFDEF WIN64}
  {.$DEFINE SUPPORTED} // TODO: Check Delphi and FPC
{$ENDIF}

{$IFDEF SUPPORTED}

{$IFDEF FPC}
  {$ALIGN 8} // For packed record
  {$MINENUMSIZE 1}
{$ELSE}
  {$IFDEF UNICODE}
    {$ALIGN 8} // For packed record
    {$MINENUMSIZE 1}

    {$IF CompilerVersion >= 25.00}{XE4Up}
      {$ZEROBASEDSTRINGS OFF}
    {$IFEND}

  {$ENDIF}
{$ENDIF}

uses
  Windows,
  Types,
  Classes,
  SysUtils,
  HVHeaps;

const
  uHVDll = 19990128; // 1999-01-28
  {$EXTERNALSYM uHVDll}
  (*
  // Sample for checking:
  // <sample>
  {$warn comparison_true off}
  {$if (not declared(uHVDll)) or (uHVDll < 19990128)}
    {$warn message_directive on}{$MESSAGE WARN 'Please use last HVDll.pas'}
    //{$MESSAGE FATAL 'Please use last HVDll.pas'}
  {$ifend}{$warnings on}
  // <\sample>
  //*)

type
  // Structures to keep the address of function variables and name/id pairs
  PPointer = ^Pointer;
  PEntry = ^TEntry;
  TEntry = packed record
    Proc: PPointer;
    case Integer of
      0 : (Name: PChar);
      1 : (ID  : LongInt);
    end;
  PEntries = ^TEntries;
  TEntries = packed array[0..High(Word)-1] of TEntry;

  // Structures to generate the per-routine thunks
  PThunk = ^TThunk;
  TThunk = packed record
    CALL  : Byte;
    OFFSET: Integer;
  end;
  PThunks = ^TThunks;
  TThunks = packed array[0..High(Word)-1] of TThunk;

  // Structure to generate the per-DLL thunks
  TThunkHeader = packed record
    PUSH   : Byte;
    VALUE  : Pointer;
    JMP    : Byte;
    OFFSET : Integer;
  end;

  // The combined per-DLL and per-routine thunks
  PThunkingCode = ^TThunkingCode;
  TThunkingCode = packed record
    ThunkHeader : TThunkHeader;
    Thunks      : TThunks;
  end;

  // The base class that provides DelayLoad capability
  TDll = class//(TObject)
  private
    FEntries  : PEntries;
    FThunkingCode: PThunkingCode;
    FCount    : Integer;
    FFullPath : string;
    FHandle   : HMODULE;
    function GetHandle: HMODULE;
    procedure SetFullPath(const Value: string);
    function GetProcs(Index: Integer): Pointer;
    procedure SetProcs(Index: Integer; Value: Pointer);
    function GetAvailable: Boolean;
    function GetLoaded: Boolean;
    function LoadProcAddrFromIndex(Index: Integer; var Addr: Pointer): Boolean;
    procedure ActivateThunks;
    function GetEntryName(Index: Integer): string;
  protected
    function LoadHandle: HMODULE; virtual;
    class procedure Error(const Msg: string; Args: array of const);
    procedure CreateThunks;
    procedure DestroyThunks;
    function HasThunk(Thunk: PThunk): Boolean;
    function GetProcAddrFromIndex(Index: Integer): Pointer;
    function DelayLoadFromThunk(Thunk: PThunk): Pointer; register;
    function DelayLoadIndex(Index: Integer): Pointer;
    function GetIndexFromThunk(Thunk: PThunk): Integer;
    function GetIndexFromProc(Proc: PPointer): Integer;
    function ValidIndex(Index: Integer): Boolean;
    procedure CheckIndex(Index: Integer);
    property Procs[Index: Integer]: Pointer read GetProcs write SetProcs;
  public
    constructor Create(const DllName: string; const Entries: array of TEntry);
    destructor Destroy; override;
    procedure Load;
    procedure Unload;
    function HasRoutine(Proc: PPointer): Boolean;
    function HookRoutine(Proc: PPointer; HookProc: Pointer; var OrgProc{: Pointer}): Boolean;
    function UnHookRoutine(Proc: PPointer; var OrgProc{: Pointer}): Boolean;
    property FullPath: string read FFullPath write SetFullPath;
    property Handle: HMODULE read GetHandle;
    property Loaded: Boolean read GetLoaded;
    property Available: Boolean read GetAvailable;
    property Count: Integer read FCount;
    property EntryName[Index: Integer]: string read GetEntryName;
  end;

  // The class that keeps a list of all created TDll instances in one place
  TDllNotifyAction = (daLoadedDll, daUnloadedDll, daLinkedRoutine);
  TDllNotifyEvent = procedure(Sender: TDll; Action: TDllNotifyAction; Index: Integer) of object;
  TDlls = class(TList)
  private
    FCodeHeap: TCodeHeap;
    FOnDllNotify: TDllNotifyEvent;
    function GetDlls(Index: Integer): TDll;
  protected
    procedure DllNotify(Sender: TDll; Action: TDllNotifyAction; Index: Integer);
    property CodeHeap: TCodeHeap read FCodeHeap;
  public
    constructor Create;
    destructor Destroy; override;
    property Dlls[Index: Integer]: TDll read GetDlls; default;
    property OnDllNotify: TDllNotifyEvent read FOnDllNotify write FOnDllNotify;
  end;

  EDllError = class(Exception);

var
  Dlls: TDlls;

{$ENDIF SUPPORTED}

implementation

{$IFDEF SUPPORTED}

{$IFDEF VER90}
const
{$ELSE}
resourcestring
{$ENDIF}
  SIndexOutOfRange      = 'DLL-entry index out of range (%d)';
  SOrdinal              = 'ordinal #';
  SCannotLoadLibrary    = 'Could not find the library: "%s"'#13#10'(%s)';
  SCannotGetProcAddress = 'Could not find the routine "%s" in the library "%s"'#13#10'(%s)';
  SCannotFindThunk      = 'Could not find the TDll object corresponding to the thunk address %p';

{ Helper routines }

function EntryToString(const Entry: TEntry): string;
begin
  if Hi(Entry.ID) <> 0
  then Result := string(Entry.Name)
  else Result := SOrdinal+IntToStr(Entry.ID);
end;

//{$IFDEF WIN64}
//procedure ThunkingTarget(ASelf, AThunk: Pointer);
//{$ELSE}
procedure ThunkingTarget;
//{$ENDIF}
const
  TThunkSize = SizeOf(TThunk);
asm
{$IFDEF WIN64}
// TODO: ...
  //.PARAMS 3
fail code !!!
  PUSH    RAX
  PUSH    RDX
  PUSH    RCX
  MOV     EAX, [ESP+12] //?12  // Self
  MOV     EDX, [ESP+16] //?16  // Thunk
  SUB     EDX, TThunkSize //TYPE TThunk // Using SizeOf(TThunk) here does not work. BASM bug?
  CALL    TDll.DelayLoadFromThunk{(Self, Thunk);}
  MOV     [ESP+16], EAX
  POP     RCX
  POP     RDX
  POP     RAX
  ADD     ESP,  8 //?
{$ENDIF WIN64}
{$IFDEF WIN32}
  // Save register-based parameters
  PUSH    EAX
  PUSH    EDX
  PUSH    ECX
{ Stack layout at this point:
  24 [Stack based parameters]
  20 [User code RetAdr]
  16 [Thunk Ret-Adr]
  12 [Self]
   8 [EAX]
   4 [EDX]
   0 [ECX] <-ESP}
  // Get the caller's return address (i.e. one of the thunks)
  MOV     EAX, [ESP+12]   // Self
  MOV     EDX, [ESP+16]   // Thunk
  // The return address is just after the thunk that
  // called us, so go back one step
  SUB     EDX, TYPE TThunk // Using SizeOf(TThunk) here does not work. BASM bug?
  // Do the rest in Pascal
  CALL    TDll.DelayLoadFromThunk{(Self, Thunk);}
  // Now patch the return address on the stack so that we "return" to the DLL routine
  MOV     [ESP+16], EAX
  // Restore register-based parameters
  POP     ECX
  POP     EDX
  POP     EAX
  // Remove the Self Pointer!
  ADD     ESP,  4
  // "Return" to the DLL!
{$ENDIF WIN32}
end;

{ TDll }

constructor TDll.Create(const DllName: string; const Entries: array of TEntry);
begin
  inherited Create;
  FFullPath := DllName;
  FEntries  := @Entries;
  FCount    := High(Entries) - Low(Entries) + 1;
  CreateThunks;
  ActivateThunks;
  Dlls.Add(Self);
end;

destructor TDll.Destroy;
begin
  Dlls.Remove(Self);
  Unload;
  DestroyThunks;
  inherited Destroy;
end;

procedure TDll.CreateThunks;
const
  CallInstruction = $E8;
  PushInstruction = $68;
  JumpInstruction = $E9;
var
  i : Integer;
begin
  // Get a memory block large enough for the thunks
  Dlls.CodeHeap.GetMem(FThunkingCode, SizeOf(TThunkHeader) + SizeOf(TThunk) * Count);

  // Generate some machine code in the thunks
  with FThunkingCode^, ThunkHeader do
  begin
    // The per-Dll thunk does this:
    // PUSH    Self
    // JMP     ThunkingTarget
    PUSH   := PushInstruction;
    VALUE  := Self;
    JMP    := JumpInstruction;
    OFFSET := PAnsiChar(@ThunkingTarget) - PAnsiChar(@Thunks[0]);
    for i := 0 to Count-1 do
      with Thunks[i] do
      begin
        // The per-entry thunk does this:
        // CALL @ThunkingCode^.ThunkHeader
        CALL   := CallInstruction;
        OFFSET := PAnsiChar(@FThunkingCode^.ThunkHeader) - PAnsiChar(@Thunks[i+1]);
      end;
  end;
end;

procedure TDll.DestroyThunks;
begin
  if Assigned(FThunkingCode) then
  begin
    Dlls.CodeHeap.FreeMem(FThunkingCode);
    FThunkingCode := nil;
  end;
end;

function TDll.DelayLoadFromThunk(Thunk: PThunk): Pointer; register;
begin
  Result := DelayLoadIndex(GetIndexFromThunk(Thunk));
end;

function TDll.DelayLoadIndex(Index: Integer): Pointer;
begin
  Result := GetProcAddrFromIndex(Index);
  FEntries^[Index].Proc^ := Result;
end;

class procedure TDll.Error(const Msg: string; Args: array of const);
begin
  raise EDllError.CreateFmt(Msg, Args);
end;

function TDll.LoadHandle: HMODULE;
begin
  if FHandle = 0 then
  begin
    FHandle := Windows.LoadLibrary(PChar(FullPath));
    if FHandle <> 0 then
      Dlls.DllNotify(Self, daLoadedDll, -1);
  end;
  Result := FHandle;
end;

function TDll.GetHandle: HMODULE;
begin
  Result := FHandle;
  if Result = 0 then
  begin
    Result := LoadHandle;
    if Result = 0 then
      Error(SCannotLoadLibrary, [FullPath, SysErrorMessage(GetLastError)]);
  end;
end;

function TDll.GetIndexFromThunk(Thunk: PThunk): Integer;
begin
  // We calculate the thunk index by subtracting the start of the array
  // and dividing by the size of the array elements
  Result := (PAnsiChar(Thunk) - PAnsiChar(@FThunkingCode^.Thunks[0])) div SizeOf(TThunk);
end;

function TDll.LoadProcAddrFromIndex(Index: Integer; var Addr: Pointer): Boolean;
begin
  Result := ValidIndex(Index);
  if Result then
  begin
    Addr := Windows.GetProcAddress(Handle, FEntries^[Index].Name);
    Result := Assigned(Addr);
    if Result then
      Dlls.DllNotify(Self, daLinkedRoutine, Index);
  end;
end;

function TDll.GetProcAddrFromIndex(Index: Integer): Pointer;
begin
  if not LoadProcAddrFromIndex(Index, Result) then
    Error(SCannotGetProcAddress, [EntryName[Index], FullPath, SysErrorMessage(GetLastError)]);
end;

function TDll.HasThunk(Thunk: PThunk): Boolean;
begin
  // The thunk belongs to us if its address is in the thunk array
  Result := (PAnsiChar(Thunk) >= PAnsiChar(@FThunkingCode^.Thunks[0])) and
            (PAnsiChar(Thunk) <= PAnsiChar(@FThunkingCode^.Thunks[Count-1]));
end;

procedure TDll.Load;
var
  i : Integer;
begin
  for i := 0 to Count-1 do
    DelayLoadIndex(i);
end;

procedure TDll.SetFullPath(const Value: string);
begin
  if CompareText(FFullPath, Value) <> 0 then
  begin
    Unload;
    FFullPath := Value;
  end;
end;

function TDll.GetEntryName(Index: Integer): string;
begin
  if ValidIndex(Index)
  then Result := EntryToString(FEntries^[Index])
  else Result := Format(SIndexOutOfRange, [Index]);
end;

procedure TDll.ActivateThunks;
// Patch the procedure variables to point to the generated thunks
var
  i : Integer;
begin
  for i := 0 to Count-1 do
    FEntries^[i].Proc^ := @FThunkingCode^.Thunks[i];
end;

procedure TDll.Unload;
begin
  ActivateThunks;
  if FHandle <> 0 then
  begin
    FreeLibrary(FHandle);
    Dlls.DllNotify(Self, daUnloadedDll, -1);
    FHandle := 0;
  end;
end;

function TDll.ValidIndex(Index: Integer): Boolean;
begin
  Result := (Index >= 0) and (Index <= Count-1);
end;

procedure TDll.CheckIndex(Index: Integer);
begin
  if not ValidIndex(Index) then
    Error(SIndexOutOfRange, [Index]);
end;

function TDll.GetProcs(Index: Integer): Pointer;
begin
  CheckIndex(Index);
  Result := FEntries^[Index].Proc^;
end;

procedure TDll.SetProcs(Index: Integer; Value: Pointer);
begin
  CheckIndex(Index);
  FEntries^[Index].Proc^ := Value;
end;

function TDll.GetAvailable: Boolean;
begin
  Result := (LoadHandle <> 0);
end;

function TDll.GetLoaded: Boolean;
begin
  Result := (FHandle <> 0);
end;

function TDll.GetIndexFromProc(Proc: PPointer): Integer;
begin
  for Result := 0 to Count-1 do
    if FEntries^[Result].Proc = Proc then
      Exit;
  Result := -1;
end;

function TDll.HasRoutine(Proc: PPointer): Boolean;
begin
  Result := Available and
            ((not HasThunk(Proc^)) or
              LoadProcAddrFromIndex(GetIndexFromProc(Proc), Proc^));
end;

function TDll.HookRoutine(Proc: PPointer; HookProc: Pointer; var OrgProc{: Pointer}): Boolean;
begin
  Result := HasRoutine(Proc);
  if Result then
  begin
    Pointer(OrgProc) := Proc^;
    Proc^   := HookProc;
  end;
end;

function TDll.UnHookRoutine(Proc: PPointer; var OrgProc{: Pointer}): Boolean;
begin
  Result := Assigned(Pointer(OrgProc));
  if Result then
  begin
    Proc^ := Pointer(OrgProc);
    Pointer(OrgProc) := nil;
  end;
end;

{ TDlls }

constructor TDlls.Create;
begin
  inherited Create;
  FCodeHeap := TCodeHeap.Create;
end;

destructor TDlls.Destroy;
var
  i : Integer;
begin
  for i := Count-1 downto 0 do
    Dlls[i].Free;
  FCodeHeap.Free;
  FCodeHeap := nil;
  inherited Destroy;
end;

procedure TDlls.DllNotify(Sender: TDll; Action: TDllNotifyAction; Index: Integer);
begin
  if Assigned(FOnDllNotify) then
    FOnDllNotify(Sender, Action, Index);
end;

function TDlls.GetDlls(Index: Integer): TDll;
begin
  Result := TDll(Items[Index]);
end;

initialization
  Dlls := TDlls.Create;
finalization
  Dlls.Free;
  Dlls := nil;
{$ENDIF SUPPORTED}
end.
