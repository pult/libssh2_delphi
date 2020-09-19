{ HVDll.pas } // version: 2020.0615.1000
unit HVDll;
//
// Support for DelayLoading of DLLs á la VC++6.0
// Written by Hallvard Vassbotn (hallvard@falcon.no), January 1999
//
//
// Latest source:  https://github.com/pult/dll_load_delay
// Base source:    http://hallvards.blogspot.com/2008/03/tdm8-delayloading-of-dlls.html
//
(*
  TODO: Win64 (x86_64) for Delphi and FPC
*)
interface

{$UNDEF SUPPORTED}
{$IFDEF WIN32}
  {$DEFINE MSWINDOWS}
  {$DEFINE SUPPORTED} // TODO: Check Delphi and FPC
{$ENDIF}
{$IFDEF WIN64}
  {$DEFINE MSWINDOWS}
  {-DEFINE SUPPORTED} ///TODO: WIN64; Check Delphi and FPC
{$ENDIF}

//{$ifdef CPU64}
//  {.$DEFINE CPUX64}
//{$else}
//  {.$DEFINE CPUX86}
//{$endif}

{$IFDEF SUPPORTED}

{$UNDEF _MINI_}
{$DEFINE _MINI_}  { optional }

{$IFDEF FPC}
  {.$WARNINGS OFF}
  {.$HINTS OFF}

  {$MODE OBJFPC}
  //{$MODE DELPHI}
  {$H+} // Huge String (not ShortString)
  {-DEFINE UNICODE}    { optional }

  {$ASMMODE INTEL}

  {$B-,R-}
  {$Q-}
  {$J+}

  {$ASSERTIONS OFF}

  {$ALIGN 8} // For packed record
  {$MINENUMSIZE 1}
{$ELSE !FPC}
  {$B-,R-}

  {$ASSERTIONS OFF}

  {$IFDEF UNICODE}
    {$ALIGN 8} // For packed record
    {$MINENUMSIZE 1}

    {$IF CompilerVersion >= 25.00}{XE4Up}
      {$ZEROBASEDSTRINGS OFF}
    {$IFEND}
  {$ENDIF}
{$ENDIF !FPC}

//{$IFOPT D+}
//  {$UNDEF _OPT_DEBUG_OFF_}
//{$ELSE}
//  {$DEFINE _OPT_DEBUG_OFF_}
//{$ENDIF}

uses
  Windows,
  {$IFNDEF FPC}
  Types,
  {$ENDIF !FPC}
  {$IFNDEF _MINI_}
  Classes,
  SysUtils,
  {$ENDIF}
  HVHeaps;

const
  uHVDll = 202006151000; // 2020-06-15 10:00
  {$EXTERNALSYM uHVDll}
  (*
  // Sample for checking:
  // <sample>
  {$ifndef fpc}{$warn comparison_true off}{$endif}
  {$if (not declared(uHVDll)) or (uHVDll < 202006151000)}
    {$ifndef fpc}{$warn message_directive on}{$endif}
      {$MESSAGE WARN 'Please use latest "HVDll.pas" from "https://github.com/pult/dll_load_delay"'}
      // or :
      //{$MESSAGE FATAL 'Please use latest "HVDll.pas" from "https://github.com/pult/dll_load_delay"'}
  {$ifend}{$warnings on}
  // <\sample>
  //*)

type
  PPointer = ^Pointer;
  // Structures to keep the address of function variables and name/id pairs
  TEntryEx = packed record
    EProc: PPointer;
    DProc: Pointer; // Reference to dummy when EProc not exists
    case Integer of
      0: (EName: PChar);
      1: (EID  : LongInt);
  end;
  PEntryEx = ^TEntryEx;

  TEntry = packed record
    Proc: PPointer;
    case Integer of
      0: (Name: PChar);
      1: (ID  : LongInt);
  end;
  PEntry = ^TEntry;

  TEntriesEx = array of TEntryEx;

  // Structures to generate the per-routine thunks
  TThunk = packed record
    CALL  : Byte;
    OFFSET: Integer;
  end;
  PThunk = ^TThunk;
  TThunks = packed array[0..High(Word)-1] of TThunk;
  PThunks = ^TThunks;

  // Structure to generate the per-DLL thunks
  TThunkHeader = packed record
    PUSH   : Byte;
    VALUE  : Pointer;
    JMP    : Byte;
    OFFSET : Integer;
  end;
  PThunkHeader=^TThunkHeader;

  // The combined per-DLL and per-routine thunks
  PThunkingCode = ^TThunkingCode;
  TThunkingCode = packed record
    ThunkHeader : TThunkHeader;
    Thunks      : TThunks;
  end;

  // The base class that provides DelayLoad capability
  TDll = class//(TObject)
  private
    FEntries  : TEntriesEx;
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
    class procedure Error(const Msg: string);
    procedure CreateThunks;
    procedure DestroyThunks;
    function HasThunk(Thunk: PThunk): Boolean;
    function GetProcAddrFromIndex(Index: Integer): Pointer;
    function DelayLoadFromThunk(Thunk: PThunk): Pointer; register;
    function DelayLoadIndex(Index: Integer): Pointer;
    function GetIndexFromThunk(Thunk: PThunk): Integer;
    function GetIndexFromProc(Proc: PPointer): Integer;
    function ValidIndex(Index: Integer): Boolean;
    function CheckIndex(Index: Integer): Boolean; //inline;
    property Procs[Index: Integer]: Pointer read GetProcs write SetProcs;
  public
    constructor Create(const DllName: string; const Entries: array of TEntryEx); overload;
    constructor Create(const DllName: string; const Entries: array of TEntry); overload;
    destructor Destroy; override;
    procedure Load;
    procedure Unload;
    function HasRoutine(Proc: PPointer): Boolean;
    function HookRoutine(Proc: PPointer; HookProc: Pointer; var OrgProc{: Pointer}): Boolean;
    function UnHookRoutine(Proc: PPointer; var OrgProc{: Pointer}): Boolean;
    property FullPath: string read FFullPath write SetFullPath;
    //property Handle: HMODULE read GetHandle;
    property Loaded: Boolean read GetLoaded;
    property Available: Boolean read GetAvailable;
    property Count: Integer read FCount;
    property EntryName[Index: Integer]: string read GetEntryName;
  end;

{$IFDEF _MINI_}
const
  MaxListSize = Maxint div 16;
type
  PPointerList = ^TPointerList;
  TPointerList = array[0..MaxListSize - 1] of Pointer;
  TList = class
  private
    FList: PPointerList;
    FCount: Integer;
    FCapacity: Integer;
  protected
    function Get(Index: Integer): Pointer;
    procedure Grow; virtual;
    procedure Put(Index: Integer; Item: Pointer);
    procedure SetCapacity(NewCapacity: Integer);
    procedure SetCount(NewCount: Integer);
  public
    destructor Destroy; override;
    function Add(Item: Pointer): Integer;
    procedure Clear; virtual;
    procedure Delete(Index: Integer);
    function IndexOf(Item: Pointer): Integer;
    function Remove(Item: Pointer): Integer;
  end;
{$ENDIF _MINI_}

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

{$IFNDEF _MINI_}
  EDllError = class(Exception);
{$ELSE}
function IntToStr(Value: LongInt{DWORD}): string;
function SysErrorMessage(ErrorCode: Cardinal; AModuleHandle: THandle = 0): string;
{$ENDIF _MINI_}

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
  SOrdinal              = 'ordinal #';
  {$IFNDEF _MINI_}
  SIndexOutOfRange      = 'DLL-entry index out of range (%d)';
  SCannotLoadLibrary    = 'Could not find the library: "%s"'#13#10'(%s)';
  SCannotGetProcAddress = 'Could not find the routine "%s" in the library "%s"'#13#10'(%s)';
//SCannotFindThunk      = 'Could not find the TDll object corresponding to the thunk address %p';
  {$ELSE}
  SIndexOutOfRange      = 'DLL-entry index out of range ';
  {$ENDIF !_MINI_}

{ Helper routines }

{$IFDEF _MINI_}
function NativeUIntToStrBuf(ANum: NativeUInt; APBuffer: PAnsiChar): Cardinal; //PAnsiChar; // "getmem.inc"
const
  MaxDigits = 20;
var
  LDigitBuffer: array[0..MaxDigits - 1] of AnsiChar;
  LCount: Cardinal;
  LDigit: NativeUInt;
begin
  {Generate the digits in the local buffer}
  LCount := 0;
  repeat
    LDigit := ANum;
    ANum := ANum div 10;
    {$hints off}
    LDigit := LDigit - ANum * 10;
    {$hints on}
    Inc(LCount);
    LDigitBuffer[MaxDigits - LCount] := AnsiChar(Ord('0') + LDigit);
  until ANum = 0;
  {Copy the digits to the output buffer and advance it}
  System.Move(LDigitBuffer[MaxDigits - LCount], APBuffer^, LCount);
  //Result := APBuffer + LCount;
  Result := LCount;
end;

function IntToStr(Value: LongInt{DWORD}): string;
var
  S: AnsiString;
  L: Cardinal;
begin
  S := ''; SetLength(S, 10);
  L := NativeUIntToStrBuf(Value, PAnsiChar(S));
  SetLength(S, L);
  Result := string(S);
end;
{$ENDIF _MINI_}

{$warnings off}
function EntryToString(const Entry: TEntryEx): string;
begin
  if Hi(Entry.EID) <> 0
  then Result := string(Entry.EName)
  else Result := SOrdinal+IntToStr(Entry.EID);
end;
{$warnings on}

//{$IFNDEF FPC}
//  {$D-}
//{$ENDIF FPC}
//
//{$IFDEF WIN64}
//procedure ThunkingTarget(ASelf, AThunk: Pointer);
//{$ELSE}
procedure ThunkingTarget; assembler;
//{$ENDIF}
const
  TThunkSize = SizeOf(TThunk);
asm
{$IFDEF WIN64}
//TODO: WIN64
  //.PARAMS 3
//fail code !!!
  PUSH    RAX
  PUSH    RDX
  PUSH    RCX
  MOV     EAX, [ESP+12] //?12  // Self
  MOV     EDX, [ESP+16] //?16  // Thunk
  SUB     EDX, TThunkSize //TYPE TThunk
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
  SUB     EDX, TYPE TThunk // Using SizeOf(TThunk) here does not work. BASM not supported it(old bug)!
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
//
//{$IFNDEF FPC}
//  {$IFNDEF _OPT_DEBUG_OFF_}
//    {$D+} // FPC: Warning: Misplaced global compiler switch, ignored
//  {$ENDIF}
//{$ENDIF FPC}

{ TDll }
constructor TDll.Create(const DllName: string; const Entries: array of TEntryEx);
var
  i: Integer;
begin
  inherited Create;
  FFullPath := DllName;
  FCount    := Length(Entries);
  if FCount > 0 then
  begin
    SetLength(FEntries, FCount);
    for i := 0 to High(Entries) do
      FEntries[i] := Entries[i];
    CreateThunks;
    ActivateThunks;
  end;
  Dlls.Add(Self);
end;

constructor TDll.Create(const DllName: string; const Entries: array of TEntry);
var
  i: Integer;
  L: PEntryEx;
  R: PEntry;
begin
  inherited Create;
  FFullPath := DllName;
  FCount    := Length(Entries);
  if FCount > 0 then
  begin
    SetLength(FEntries, FCount);
    L := @FEntries[0];
    R := @Entries[0];
    for i := High(Entries) downto 0 do
    begin
      //FEntries[i].EProc := Entries[i].Proc;
      //FEntries[i].EID := Entries[i].ID;
      //FEntries[i].EName := Entries[i].Name;
      L^.EProc := R^.Proc;
      L^.EID := R^.ID;
      L^.EName := R^.Name;
      Inc(L);
      Inc(R);
    end;
    CreateThunks;
    ActivateThunks;
  end;
  Dlls.Add(Self);
end;

destructor TDll.Destroy;
begin
  Dlls.Remove(Self);
  Unload;
  DestroyThunks;
  inherited Destroy;
end;

procedure TDll.CreateThunks; //TODO: WIN64
const
  CallInstruction = $E8;
  PushInstruction = $68;
  JumpInstruction = $E9;
var
  i: Integer;
  Size: DWORD;
  H: PThunkHeader;
  T, T1: PThunk;
begin
  if Count = 0 then
    Exit;
  // Get a memory block large enough for the thunks
  Size := SizeOf(TThunkHeader) + SizeOf(TThunk) * Count;
  Dlls.CodeHeap.GetMem(FThunkingCode, Size);

  // Generate some machine code in the thunks
  //with FThunkingCode^{, ThunkHeader} do
  begin
    // The per-Dll thunk does this:
    // PUSH    Self
    // JMP     ThunkingTarget
    H := @FThunkingCode^.ThunkHeader;
    H^.PUSH   := PushInstruction;
    H^.VALUE  := Self;
    H^.JMP    := JumpInstruction;

    T := @FThunkingCode^.Thunks[0];
    H^.OFFSET := PAnsiChar(@ThunkingTarget) - PAnsiChar(T);

    T1 := T; Inc(T1); //T1 := @FThunkingCode^.Thunks[1];
    for i := 0 to Count-1 do
    begin
      //T := @FThunkingCode^.Thunks[i]; T1 := @FThunkingCode^.Thunks[i+1];
      // The per-entry thunk does this:
      // CALL @ThunkingCode^.ThunkHeader
      T^.CALL   := CallInstruction;
      T^.OFFSET := PAnsiChar(H) - PAnsiChar(T1);
      //
      Inc(T); Inc(T1);
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
  if Assigned(Result) then
    FEntries[Index].EProc^ := Result
  else
    FEntries[Index].EProc^ := FEntries[Index].DProc
  ;
end;

class procedure TDll.Error(const Msg: string);
begin
  {$IFNDEF _MINI_}
  raise EDllError.Create(Msg);
  {$ELSE}
  {$IFDEF UNICODE}
  OutputDebugStringW(PWideChar(UnicodeString('ERROR: TDll: ' + Msg)));
  {$ELSE}
  OutputDebugStringA(PAnsiChar(AnsiString('ERROR: TDll: ' + Msg)));
  {$ENDIF}
  if IsConsole then
    writeln('ERROR: ', Msg)
  {$IFDEF DEBUG}
  else
    {$IFDEF UNICODE}
    MessageBoxW(0, PWideChar(UnicodeString(Msg)), {Caption:}nil, MB_OK or MB_ICONERROR)
    {$ELSE}
    MessageBoxA(0, PAnsiChar(AnsiString(Msg)), {Caption:}nil, MB_OK or MB_ICONERROR)
    {$ENDIF}
  {$ENDIF}
  ;
  Halt(1);
  {$ENDIF _MINI_}
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

{$IFDEF _MINI_}
{$hints off}
function SysErrorMessage(ErrorCode: Cardinal; AModuleHandle: THandle = 0): string;
var
  Buffer: {$IFDEF UNICODE}PWideChar{$ELSE}PAnsiChar{$ENDIF};
  Len: Integer;
  Flags: DWORD;
  U: {$IFDEF UNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  Flags := FORMAT_MESSAGE_FROM_SYSTEM or
    FORMAT_MESSAGE_IGNORE_INSERTS or
    FORMAT_MESSAGE_ARGUMENT_ARRAY or
    FORMAT_MESSAGE_ALLOCATE_BUFFER;

  if AModuleHandle <> 0 then
    Flags := Flags or FORMAT_MESSAGE_FROM_HMODULE;

  { Obtain the formatted message for the given Win32 ErrorCode
    Let the OS initialize the Buffer variable. Need to LocalFree it afterward.
  }
  {$IFDEF UNICODE}
  Len := FormatMessageW(Flags, Pointer(AModuleHandle), ErrorCode, 0, @Buffer, 0, nil);
  {$ELSE}
  Len := FormatMessageA(Flags, Pointer(AModuleHandle), ErrorCode, 0, @Buffer, 0, nil);
  {$ENDIF};

  try
    { Remove the undesired line breaks and '.' char }
    {$IFDEF UNICODE}
    while (Len > 0) and ((Buffer[Len - 1] <= WideChar(#32)) or (Buffer[Len - 1] = WideChar('.'))) do
    {$ELSE}
    while (Len > 0) and ((Buffer[Len - 1] <= AnsiChar(#32)) or (Buffer[Len - 1] = AnsiChar('.'))) do
    {$ENDIF};
      Dec(Len);
    { Convert to Delphi string }
    SetString(U, Buffer, Len);
    Result := string(U);
  finally
    { Free the OS allocated memory block }
    LocalFree(HLOCAL(Buffer));
  end;
end;
{$hints on}
{$ENDIF _MINI_}

function TDll.GetHandle: HMODULE;
begin
  Result := FHandle;
  if Result = 0 then
  begin
    Result := LoadHandle();
    if Result = 0 then
      {$IFNDEF _MINI_}
      Error(Format(SCannotLoadLibrary, [FullPath, SysErrorMessage(GetLastError)]));
      {$ELSE}
      Error(
        'Could not find the library: "' + FullPath + '"'#13#10'(' + SysErrorMessage(GetLastError()) + ')'
      );
      {$ENDIF _MINI_}
  end;
end;

function TDll.GetIndexFromThunk(Thunk: PThunk): Integer;
begin
  // We calculate the thunk index by subtracting the start of the array
  // and dividing by the size of the array elements
  Result := (PAnsiChar(Thunk) - PAnsiChar(@FThunkingCode^.Thunks[0])) div SizeOf(TThunk);
end;

function TDll.LoadProcAddrFromIndex(Index: Integer; var Addr: Pointer): Boolean;
var
  H: HMODULE;
begin
  Result := ValidIndex(Index);
  if Result then
  begin
    H := GetHandle(); // Handle
    Result := H <> 0;
    if Result then
    begin
      Addr := Windows.GetProcAddress(H, FEntries[Index].EName);
      Result := Assigned(Addr);
      if not Result then
      begin
        Addr := FEntries[Index].DProc;
        Result := Assigned(Addr);
      end;
      if Result then
        Dlls.DllNotify(Self, daLinkedRoutine, Index);
    end;
  end;
end;

function TDll.GetProcAddrFromIndex(Index: Integer): Pointer;
begin
//  {$hints off}
  Result := nil;
  if not LoadProcAddrFromIndex(Index, Result) then
  begin
    {$IFNDEF _MINI_}
    Error(Format(SCannotGetProcAddress, [EntryName[Index], FullPath, SysErrorMessage(GetLastError)]));
    {$ELSE}
    Error(
      'Could not find the routine "'+EntryName[Index]+'" in the library "'+FullPath+'"'#13#10'('+SysErrorMessage(GetLastError())+')'
    );
    {$ENDIF !_MINI_}
  end;
//  {$hints on}
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

function AnsiCompareText(const S1, S2: string): Integer;
begin
  Result := CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE, PChar(S1),
    Length(S1), PChar(S2), Length(S2)) - 2;
end;

function CompareText(const S1, S2: string): Integer;
begin
  Result := AnsiCompareText(S1, S2);
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
  then Result := EntryToString(FEntries[Index])
  {$IFNDEF _MINI_}
  else Result := Format(SIndexOutOfRange, [Index]);
  {$ELSE}
  else Result := SIndexOutOfRange + '(' + IntToStr(Index) + ')';
  {$ENDIF _MINI_}
end;

procedure TDll.ActivateThunks;
// Patch the procedure variables to point to the generated thunks
var
  i : Integer;
  E: PEntryEx;
  //T: PThunks;
begin
  //for i := 0 to Count-1 do
  //  if Assigned(FEntries[i].EProc) then
  //    FEntries[i].EProc^ := @FThunkingCode^.Thunks[i];
  //Exit;

  if Count = 0 then
    Exit;
  E := @FEntries[0];
  //T := @FThunkingCode^.Thunks[0];
  //for i := Count-1 downto 0 do
  for i := 0 to Count-1 do
  begin
    if Assigned(E^.EProc) then
      //--E^.EProc^ := T;
      E^.EProc^ := @FThunkingCode^.Thunks[i];
    Inc(E);
    //--Inc(T);
  end;
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

function TDll.CheckIndex(Index: Integer): Boolean;
begin
  Result := ValidIndex(Index);
  if not Result then
    {$IFNDEF _MINI_}
    Error(Format(SIndexOutOfRange, [Index]));
    {$ELSE}
    Error(
      'DLL-entry index out of range ('+IntToStr(Index)+')'
    );
    {$ENDIF !_MINI_}
end;

function TDll.GetProcs(Index: Integer): Pointer;
begin
  if CheckIndex(Index) then
    Result := FEntries[Index].EProc^
  else
    Result := nil;
end;

procedure TDll.SetProcs(Index: Integer; Value: Pointer);
begin
  if CheckIndex(Index) then
    FEntries[Index].EProc^ := Value;
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
var
  E: PEntryEx;
begin
  if Assigned(Proc) then
  begin
    for Result := 0 to Count-1 do
    begin
      E := @FEntries[Result];
      if (E^.EProc = Proc) or (E^.DProc = Proc) then
        Exit;
    end;
  end;
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

{$IFDEF _MINI_}

{ TList }

destructor TList.Destroy;
begin
  Clear;
  inherited;
end;

function TList.Add(Item: Pointer): Integer;
begin
  Result := FCount;
  if Result = FCapacity then
    Grow;
  FList^[Result] := Item;
  Inc(FCount);
end;

procedure TList.Clear;
begin
  SetCount(0);
  SetCapacity(0);
end;

procedure TList.Delete(Index: Integer);
begin
  if (Index < 0) or (Index >= FCount) then
    Exit; //Error(@SListIndexError, Index);
  Dec(FCount);
  if Index < FCount then
    System.Move(FList^[Index + 1], FList^[Index],
      (FCount - Index) * SizeOf(Pointer));
end;

function TList.Get(Index: Integer): Pointer;
begin
  if (Index < 0) or (Index >= FCount) then
    Result := nil //Error(@SListIndexError, Index)
  else
    Result := FList^[Index];
end;

procedure TList.Grow;
var
  Delta: Integer;
begin
  if FCapacity > 64 then
    Delta := FCapacity div 4
  else
    if FCapacity > 8 then
      Delta := 16
    else
      Delta := 4;
  SetCapacity(FCapacity + Delta);
end;

function TList.IndexOf(Item: Pointer): Integer;
begin
  Result := 0;
  while (Result < FCount) and (FList^[Result] <> Item) do
    Inc(Result);
  if Result = FCount then
    Result := -1;
end;

procedure TList.Put(Index: Integer; Item: Pointer);
begin
  if (Index < 0) or (Index >= FCount) then
    Exit; //Error(@SListIndexError, Index);
  if Item <> FList^[Index] then
    FList^[Index] := Item;
end;

function TList.Remove(Item: Pointer): Integer;
begin
  Result := IndexOf(Item);
  if Result >= 0 then
    Delete(Result);
end;

procedure TList.SetCapacity(NewCapacity: Integer);
begin
  if (NewCapacity < FCount) or (NewCapacity > MaxListSize) then
    Exit; //Error(@SListCapacityError, NewCapacity);
  if NewCapacity <> FCapacity then
  begin
    ReallocMem(FList, NewCapacity * SizeOf(Pointer));
    FCapacity := NewCapacity;
  end;
end;

procedure TList.SetCount(NewCount: Integer);
var
  I: Integer;
begin
  if (NewCount < 0) or (NewCount > MaxListSize) then
    Exit; //Error(@SListCountError, NewCount);
  if NewCount > FCapacity then
    SetCapacity(NewCount);
  if NewCount > FCount then
    FillChar(FList^[FCount], (NewCount - FCount) * SizeOf(Pointer), 0)
  else
    for I := FCount - 1 downto NewCount do
      Delete(I);
  FCount := NewCount;
end;

{$ENDIF _MINI_}

{ TDlls }

constructor TDlls.Create;
begin
  inherited Create;
  FCodeHeap := TCodeHeap.Create;
end;

destructor TDlls.Destroy;
var
  i: Integer;
  Obj: TObject;
begin
  for i := FCount-1 downto 0 do
  begin
    Obj := Dlls[i];
    FList^[i] := nil; // Put(i, nil);
    Obj.Free;
  end;
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
  Result := TDll(Get(Index));
end;

initialization
  Dlls := TDlls.Create;
finalization
  try
    Dlls.Free;
  except
  end;
  Dlls := nil;
{$ENDIF SUPPORTED}
end.
