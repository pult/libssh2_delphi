{ HVDll.pas } //# version: 2024.0114.1600
unit HVDll;
//#
//# Support for DelayLoading of DLLs la "VC++ 6.0"
//# Written by Hallvard Vassbotn (hallvard@falcon.no), January 1999.
//#
//# Latest source: https://github.com/pult/dll_load_delay
//# Base source:   http://hallvards.blogspot.com/2008/03/tdm8-delayloading-of-dlls.html
//#
interface

{$UNDEF SUPPORTED}
{$IFDEF WIN32}
  {$DEFINE MSWINDOWS}
  {$DEFINE SUPPORTED} //#TODO: Check FPC.
{$ENDIF}
{$IFDEF WIN64}
  {$DEFINE MSWINDOWS}
  //#
  //#TEST:
  //#
  {$if defined(_IDE_) and defined(_DEBUG_) and defined(_TEST_)}
    {-DEFINE SUPPORTED} //#TODO: WIN64: Check Delphi and FPC
  {$ifend}
  //#
  //#TEST.
  //#
{$ENDIF}

//{$ifdef CPU64}
//  {-DEFINE CPUX64}
//{$else}
//  {-DEFINE CPUX86}
//{$endif}

{$IFDEF SUPPORTED}

{$UNDEF _TEST_} //@dbg

{$UNDEF _MINI_}
{$DEFINE _MINI_} { optional }

{$undef allow_inline} { no change }
{$define allow_inline} { optional }

{$IFDEF FPC}
  {-WARNINGS OFF}
  {-HINTS OFF}

  {$MODE OBJFPC}
  {-MODE DELPHI}
  {$H+} //# Huge String (not ShortString)
  {-DEFINE UNICODE} { optional }

  {$ASMMODE INTEL}

  {$B-,R-}
  {$Q-}
  {$J+}

  {$ASSERTIONS OFF}

  {$ALIGN 8} //# For packed record
  {$MINENUMSIZE 1}
{$ELSE  !FPC}
  {$B-,R-}

  {$ASSERTIONS OFF}

  {$IFDEF UNICODE}
    {$ALIGN 8} //# For packed record
    {$MINENUMSIZE 1}

    {$WARN UNSAFE_CAST OFF} // W1048 Unsafe typecast of '*' to '*'

    {$IFDEF CONDITIONALEXPRESSIONS}
      {$IF CompilerVersion >= 25.00}{XE4Up}
        {$ZEROBASEDSTRINGS OFF}
        {$undef allow_inline} { no change }
        {$IF CompilerVersion >= 33.00}
          {$WARN EXPLICIT_STRING_CAST OFF}       // W1059 Explicit string cast from 'AnsiString' to 'string'
          {$WARN IMPLICIT_INTEGER_CAST_LOSS OFF} // W1071 Implicit integer cast with potential data loss from '*' to '*'
        {$IFEND}
      {$ELSE}
      {$IFEND}
    {$ELSE}
      {$undef allow_inline} { no change }
    {$ENDIF}

  {$ELSE  !UNICODE}
  {$ENDIF !UNICODE}
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
  {$IFDEF _MINI_}
  SysUtils, // optional
  {$ELSE}
  Classes,
  SysUtils,
  {$ENDIF}
  HVHeaps;

const
  HVDLL_VERSION = 202401141600;
  //# format    : yyyymmddhhnn #
  {$EXTERNALSYM HVDLL_VERSION}
  uHVDll = HVDLL_VERSION // {$if defined(FPC) or (CompilerVersion >= 18.50)} deprecated{$ifend}
    // {$if defined(FPC) or (CompilerVersion >= 24.00)}
    // 'Symbol uHVDll is considered deprecated. Use HVDLL_VERSION'
    // {$ifend}
  ;
  {$EXTERNALSYM uHVDll}
  (*
  //# Sample for checking:
  //# <sample>
  //#
  {$ifndef fpc}{$warn comparison_true off}{$endif}
  {$if (not declared(HVDLL_VERSION)) or (HVDLL_VERSION < 2024011401600)}
    {$ifndef fpc}{$warn message_directive on}{$endif}
      {$MESSAGE WARN 'Please use latest "HVDll.pas" from "https://github.com/pult/dll_load_delay"'}
      // or :
      //{$MESSAGE FATAL 'Please use latest "HVDll.pas" from "https://github.com/pult/dll_load_delay"'}
  {$ifend}{$warnings on}
  //#
  //# <\sample>
  //*)
type
  {$if declared(Exception)}
  EDllError = class(Exception);
  {$ifend}

  PPointer = ^Pointer;
  //# Structures to keep the address of function variables and name/id pairs
  TEntryEx = record
    EProc: PPointer;
    DProc: Pointer; //# Reference to dummy when EProc not exists
    case Integer of
      0: (EName: PChar);
      1: (EID  : LongInt);
  end;
  PEntryEx = ^TEntryEx;

  TEntry = record
    Proc: PPointer;
    case Integer of
      0: (Name: PChar);
      1: (ID  : LongInt);
  end;
  PEntry = ^TEntry;

  TEntriesEx = array of TEntryEx;

  //# Structures to generate the per-routine thunks
  TThunk = packed record
    CALL  : Byte;
    OFFSET: Integer;
  end;
  PThunk = ^TThunk;
  TThunks = packed array[0..High(Word)-1] of TThunk;
  PThunks = ^TThunks;

  //# Structure to generate the per-DLL thunks
  TThunkHeader = packed record
    PUSH   : Byte;
    VALUE  : Pointer;
    JMP    : Byte;
    OFFSET : Integer;
  end;
  PThunkHeader=^TThunkHeader;

  //# The combined per-DLL and per-routine thunks
  PThunkingCode = ^TThunkingCode;
  TThunkingCode = packed record
    ThunkHeader : TThunkHeader;
    Thunks      : TThunks;
  end{ align 8};

  //# The base class that provides DelayLoad capability
  TDll = class
  private
    FShortName    : string;
    FCount        : Integer;
    FHandle       : HMODULE;
    FDllFinalize  : Boolean;
    FFullPath     : string;
    FThunkingCode : PThunkingCode;
    FEntries      : TEntriesEx;

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
    class procedure DoError(const Msg: string; Show: Boolean{ = True}; Warn: Boolean{ = False});
    class procedure Error(const Msg: string); {$ifdef allow_inline}inline;{$endif}
    class procedure Warning(const Msg: string); {$ifdef allow_inline}inline;{$endif}
    procedure CreateThunks;
    procedure DestroyThunks;
    function HasThunk(Thunk: PThunk): Boolean;
    function GetProcAddrFromIndex(Index: Integer): Pointer;
    function DelayLoadFromThunk(Thunk: PThunk): Pointer; {$IFDEF WIN32}register;{$ENDIF}
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
    property ShortName: string read FShortName;
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
  TPointerList = array[0..MaxListSize - 1] of Pointer;
  PPointerList = ^TPointerList;
  TList = class
  private
    FList     : PPointerList;
    FCount    : Integer;
    FCapacity : Integer;
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

    property Count: Integer read FCount write SetCount;
  end;
{$ENDIF _MINI_}

  // The class that keeps a list of all created TDll instances in one place
  TDllNotifyAction = (daLoadedDll, daUnloadedDll, daLinkedRoutine);
  TDllNotifyEvent = procedure(Sender: TDll; Action: TDllNotifyAction; Index: Integer) of object;
  TDlls = class(TList)
  private
    FCodeHeap    : TCodeHeap;
    FOnDllNotify : TDllNotifyEvent;
    FDllFinalize : Boolean;

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

{$IFDEF _MINI_}
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
  LCount: Cardinal; LDigit: NativeUInt;
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
var S: AnsiString; L: Cardinal;
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
(*=  //# @dbg: PUREPASCAL
procedure ThunkingTarget;
var ADll: TDll; AThunk: PThunk;
  {$IFDEF  WIN64}
  procedure asm__save_regs; assembler; asm .NOFRAME;
  end;
  procedure asm__restore_regs; assembler; asm .NOFRAME;
  end;
  {$ENDIF !WIN64}
begin //# X64: ++ tobject(pnativeint(RSP+8*0)^).classname  #  ++ PThunk(pnativeint(RSP+8*1)^)^,r  # (CALL:232; OFFSET:-24) # RBP-RSP = 24
      //#      ++ tobject(pnativeint(RBP-8*3)^).classname  #  ++ PThunk(pnativeint(RBP-8*2)^)^,r # (CALL:232; OFFSET:-24) # RBP-RSP = 24
  {$IFDEF  WIN64} //-//# X64: ++ tobject(pnativeint(RBP+8*5)^).classname  #  -- PThunk(pnativeint(RBP+8*6))^
      //#      ++ tobject(pnativeint(8*7+RBP)^).classname  #  ++ PThunk(pnativeint(8*8+RBP)^)^,r # (CALL:232; OFFSET:-24) # RBP-RSP = 24
      //#      40: nativeint(pointer(@ADll))-nativeint(RBP)#  32: nativeint(pointer(@AThunk))-nativeint(RBP)
      //#      nativeint(pointer(@ADll))-40=nativeint(RBP) # nativeint(pointer(@AThunk))-32=nativeint(RBP)

      //asm__save_regs();

      ADll   := TDll  (  pnativeint(  8*7 + nativeint(  (nativeint(pointer(@ADll  ))-40)  )  )^  )
      ;
      //-AThunk := PThunk(  pnativeint(  8*8 + nativeint(  (nativeint(pointer(@AThunk))-32)  )  )^  )
      //-Dec(AThunk);
      //# or:
      AThunk := PThunk(  pnativeint(  8*8 + nativeint(  (nativeint(pointer(@AThunk))-32)  )  )^-SizeOf(TThunk)  )
      ;
      {
      // MOV     [RSP+32], RAX //# @dbg: Thunk: PThunk(ppointer(RSP+32)^)^ , r  #  Addr: rax = nativeint(@test_libssh2_init)
      //asm__restore_regs();
      MOV     [RSP+32], RAX
      // Remove the Self Pointer!
      ADD     RSP,  8
      //# @dbg: Thunk: ppointer(RSP)^  =  @test_libssh2_init
      }
  //#-- X64: tobject(pnativeint(RSP+8*0)^).classname
  //#-- X64: tobject(pnativeint(RBP+08)^).classname  #  nativeint(pointer(@ADll))-nativeint(RBP+08)
//  asm__sub_rbp40; //# tobject(ppointer(nativeint(@ADll)-8)^).classname
  {$ELSE  !WIN64}
  //# X86: tobject(pinteger(EBP+04)^).classname  #  integer(pointer(@ADll))-integer(ESP+04)
  asm add ebp, -4 end;
  {$ENDIF !WIN64}
  ADll.DelayLoadFromThunk(AThunk); // nativeint(@ADll) - 1374992
  //...
end; //=*){=
(*=} //# ASM CODE:
procedure ThunkingTarget; assembler;
//{$ENDIF}
const TThunkSize = SizeOf(TThunk);
{$IFDEF WIN64} //# *** *** *** WIN 32 *** *** ***
//#TODO: WIN64 : failed code !!!
const SZREGS = 8*(0+(3+4)); //# protect override saved rax and added for saved regs
{$IFDEF FPC}
  nostackframe;
asm
{$ELSE}
asm
  .NOFRAME
{$ENDIF}
//(* //# VER #003: partial work
  push rbp
  sub rsp,$30+SZREGS
  mov rbp,rsp

//  PUSH    RAX  //#TODO: Failed restored RCX...
//  PUSH    RDX
//  PUSH    RCX
  mov [rbp+$28+8*0],rax   //# Try restored RCX
  mov [rbp+$28+8*1],rdx
  mov [rbp+$28+8*2],rcx
  //
//  mov [rbp+$28+8*3],r8
//  mov [rbp+$28+8*4],r9
//  mov [rbp+$28+8*5],r10
//  mov [rbp+$28+8*6],r11

  //# ADll   := TDll  (  pnativeint(  8*7 + nativeint(  (nativeint(pointer(@ADll  ))-40)  )  )^  )
  mov rax,[rbp+$38+SZREGS]
  mov [rbp+$28+SZREGS],rax
  //# AThunk := PThunk(  pnativeint(  8*8 + nativeint(  (nativeint(pointer(@AThunk))-32)  )  )^-SizeOf(TThunk)  )
  mov rax,[rbp+$40+SZREGS]
  lea rax,[rax-$05]
  mov [rbp+$20+SZREGS],rax
  //# ADll.DelayLoadFromThunk(AThunk); // nativeint(@ADll) - 1374992
  mov rcx,[rbp+$28+SZREGS]
  mov rdx,[rbp+$20+SZREGS]
//ADD RSP, -8*10
  call TDll.DelayLoadFromThunk
//ADD RSP, +8*10
  MOV     [RBP+$30+SZREGS-16+32], RAX //# @dbg: Thunk: PThunk(ppointer(RSP+32)^)^ , r  #  Addr: rax = nativeint(@test_libssh2_init)

//  POP     RCX
//  POP     RDX
//  POP     RAX

//  mov r11,[rbp+$28+8*6]
//  mov r10,[rbp+$28+8*5]
//  mov r9,[rbp+$28+8*4]
//  mov r8,[rbp+$28+8*3]
  //
  mov rcx, [rbp+$28+8*2]
  mov rdx, [rbp+$28+8*1]
  mov rax, [rbp+$28+8*0]

  //# ret
  lea rsp,[rbp+$30+SZREGS]
  pop rbp

  //# Remove the Self Pointer!
  ADD     RSP,  8

//#TODO: ACCESS_VIOLATION # Failed call "ws2_32.dll" getaddrinfo by "uMySFTPClient.pas":
//#                                          function TSSH2Client.ConnectSocket
//#                                              getaddrinfo(PAnsiChar(

  ret
//*)

(* //# VER #002: failed rasrore regs RCX...
  push rbp
  sub rsp,$30
  mov rbp,rsp

  PUSH    RAX
  PUSH    RDX
  PUSH    RCX

  //# ADll   := TDll  (  pnativeint(  8*7 + nativeint(  (nativeint(pointer(@ADll  ))-40)  )  )^  )
  mov rax,[rbp+$38]
  mov [rbp+$28],rax
  //# AThunk := PThunk(  pnativeint(  8*8 + nativeint(  (nativeint(pointer(@AThunk))-32)  )  )^-SizeOf(TThunk)  )
  mov rax,[rbp+$40]
  lea rax,[rax-$05]
  mov [rbp+$20],rax
  //# ADll.DelayLoadFromThunk(AThunk); // nativeint(@ADll) - 1374992
  mov rcx,[rbp+$28]
  mov rdx,[rbp+$20]
  call TDll.DelayLoadFromThunk
  MOV     [RBP+$30-16+32], RAX //# @dbg: Thunk: PThunk(ppointer(RSP+32)^)^ , r  #  Addr: rax = nativeint(@test_libssh2_init)

  POP     RCX
  POP     RDX
  POP     RAX

  //# ret
  lea rsp,[rbp+$30]
  pop rbp

  //# Remove the Self Pointer!
  ADD     RSP,  8

  ret
//*)

//# VER #001: failed rasrore regs RCX...
//PUSH    RAX
//PUSH    RDX
//PUSH    RCX

//# @dbg: Self:   TObject(ppointer(RSP+0)^).ClassName
//# @dbg: Thunk:  PThunk(ppointer(RSP+8)^)^ ,r
//# @dbg: Index:  ((nativeint(ppointer(RSP+8)^)-TThunkSize) - nativeint(@(TDll(ppointer(RSP+0)^).FThunkingCode^.Thunks[0]))) div TThunkSize

  PUSH    RAX
  PUSH    RDX
  PUSH    RCX
{ Stack layout at this point:
  48 [Stack based parameters]  //# pnativeint(RSP+48)^
  40 [User code RetAdr]        //# pnativeint(RSP+40)^
  32 [Thunk Ret-Adr]           //# pnativeint(RSP+32)^
  24 [Self]                    //# pnativeint(RSP+24)^
  16 [RAX]                     //# pnativeint(RSP+16)^
   8 [RDX]                     //# pnativeint(RSP+08)^
   0 [RCX] <-RSP}              //# pnativeint(RSP+00)^

//# @dbg: Self:   TObject(ppointer(ESP+24)^).ClassName
//# @dbg: Thunk:  PThunk(ppointer(ESP+32)^)^ ,r
//# @dbg: Index:  ((nativeint(ppointer(RSP+32)^)-TThunkSize) - nativeint(@(TDll(RAX).FThunkingCode^.Thunks[0]))) div TThunkSize

  // Get the caller's return address (i.e. one of the thunks)
  MOV     RCX, [RSP+24] //# Self: TObject(ppointer(ESP+24)^).ClassName
//MOV RCX, RAX //?!!
  MOV     RDX, [RSP+32] //# Thunk
  SUB     RDX, TThunkSize //# TYPE TThunk
//# @dbg: Self:   TObject(RAX).ClassName = 'TDll'
//? @dbg: Self:   TObject(RCX).ClassName = 'TDll'
//# @dbg: Thunk:  PThunk(RDX)^ ,r
//# @dbg: Index: (RDX - nativeint(@(TDll(RAX).FThunkingCode^.Thunks[0]))) div TThunkSize

//ADD RSP, -$40 // $40 == 64 == 8*8 //# DelayLoadFromThunk incremented RSP
  CALL    TDll.DelayLoadFromThunk //# (Self, Thunk)  #  changed: rcx rdx r8 r9 r10 r11
//ADD RSP, +$40 // 8*8

  MOV     [RSP+32], RAX //# @dbg: Thunk: PThunk(ppointer(RSP+32)^)^ , r  #  Addr: rax = nativeint(@test_libssh2_init)

  POP     RCX
  POP     RDX
  POP     RAX
//# @dbg: Thunk: nativeint(ppointer(RSP+8)^)  =  nativeint(@test_libssh2_init)
//POP     RCX
//POP     RDX
//POP     RAX

  // Remove the Self Pointer!
  ADD     RSP,  8
//# @dbg: Thunk: ppointer(RSP)^  =  @test_libssh2_init
  // "Return" to the DLL!
{$ENDIF WIN64}
{$IFDEF WIN32} //# *** *** *** WIN 32 *** *** ***
asm
  // Save register-based parameters
  PUSH    EAX
  PUSH    EDX
  PUSH    ECX
{ Stack layout at this point:
  24 [Stack based parameters]  //# pinteger(ESP+24)^
  20 [User code RetAdr]        //# pinteger(ESP+20)^
  16 [Thunk Ret-Adr]           //# pinteger(ESP+16)^
  12 [Self]                    //# pinteger(ESP+12)^
   8 [EAX]                     //# pinteger(ESP+08)^
   4 [EDX]                     //# pinteger(ESP+04)^
   0 [ECX] <-ESP}              //# pinteger(ESP+00)^
  // Get the caller's return address (i.e. one of the thunks)
  MOV     EAX, [ESP+12]   // Self
  MOV     EDX, [ESP+16]   // Thunk
  // The return address is just after the thunk that
  // called us, so go back one step
  SUB     EDX, TYPE TThunk // Using SizeOf(TThunk) here does not work. BASM not supported it(old bug)!
  // Do the rest in Pascal

//-ADD ESP,-$20
  CALL    TDll.DelayLoadFromThunk{(Self, Thunk);} //@dbg: PThunk(EDX)^ ; TObject(EAX).ClassName = 'TDll'
//-ADD ESP,+$20

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
end; //*)
//
//{$IFNDEF FPC}
//  {$IFNDEF _OPT_DEBUG_OFF_}
//    {$D+} // FPC: Warning: Misplaced global compiler switch, ignored
//  {$ENDIF}
//{$ENDIF FPC}

{ TDll }

constructor TDll.Create(const DllName: string; const Entries: array of TEntryEx);
var i: Integer;
begin
  inherited Create;
  SetFullPath(DllName);
  FCount   := Length(Entries);
  if FCount > 0 then begin
    SetLength(FEntries, FCount);
    for i := 0 to High(Entries) do begin
      FEntries[i] := Entries[i];
    end;
    CreateThunks;
    ActivateThunks;
  end;
  Dlls.Add(Self);
end;

constructor TDll.Create(const DllName: string; const Entries: array of TEntry);
var i: Integer; L: PEntryEx; R: PEntry;
begin
  inherited Create;
  SetFullPath(DllName);
  FCount    := Length(Entries);
  if FCount > 0 then begin
    SetLength(FEntries, FCount);
    L := @FEntries[0];
    R := @Entries[0];
    for i := High(Entries) downto 0 do begin
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
var i: Integer;
begin
  //-if Assigned(Dlls) then
  begin
    i := Dlls.IndexOf(Self);
    if i >= 0
    then Dlls.Delete(i)
    else TDll.DoError('"'+FShortName+'": - Failed owned', {Show:}False, {Warn:}False);
  end;
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
  i: Integer; Size: DWORD; H: PThunkHeader; T, T1: PThunk;
begin
  if Count = 0 then
    Exit;
  // Get a memory block large enough for the thunks
  Size := SizeOf(TThunkHeader) + SizeOf(TThunk) * Cardinal(Count);
  Dlls.CodeHeap.GetMem(FThunkingCode, Size);

  //# Generate some machine code in the thunks
  //-with FThunkingCode^{, ThunkHeader} do
  begin
    //# The per-Dll thunk does this:
    //# PUSH    Self
    //# JMP     ThunkingTarget
    H := @FThunkingCode^.ThunkHeader;
    H^.PUSH   := PushInstruction;
    H^.VALUE  := Self;
    H^.JMP    := JumpInstruction;

    T := @FThunkingCode^.Thunks[0];
    H^.OFFSET := PAnsiChar(@ThunkingTarget) - PAnsiChar(T);

    T1 := T; Inc(T1); //T1 := @FThunkingCode^.Thunks[1];
    for i := 0 to Count-1 do begin
      //T := @FThunkingCode^.Thunks[i]; T1 := @FThunkingCode^.Thunks[i+1];
      //# The per-entry thunk does this:
      //# CALL @ThunkingCode^.ThunkHeader
      T^.CALL   := CallInstruction;
      T^.OFFSET := PAnsiChar(H) - PAnsiChar(T1);
      //
      Inc(T); Inc(T1);
    end;
  end;
end;

procedure TDll.DestroyThunks; var P: Pointer;
begin
  if Assigned(FThunkingCode) then begin
    P := FThunkingCode; FThunkingCode := nil;
    if not Dlls.CodeHeap.FreeMem(P) then
      TDll.DoError('"'+FShortName+'": - Failed FreeMem', {Show:}False, {Warn:}False);
  end;
end;

//#TEST:
{$if defined(_IDE_) and defined(_DEBUG_) and defined(_TEST_)}
//{ //# optional:
type t_libssh2_init = function(flags: Integer): Integer; cdecl;
var _test_libssh2_init: t_libssh2_init;
function test_libssh2_init(flags: Integer): Integer; cdecl;
begin
  Result := _test_libssh2_init(flags);
end;
//}
{$ifend}
//#TEST.

function TDll.DelayLoadFromThunk(Thunk: PThunk): Pointer;
//begin Result := DelayLoadIndex(GetIndexFromThunk(Thunk)); end; (*
var i: integer;
begin //@dbg: Thunk^ ,r
  if FDllFinalize then
    TDll.Error('Module HVDll uninitialized');

  i := GetIndexFromThunk(Thunk); //@dbg: FEntries[i].EName
  Result := DelayLoadIndex(i);

  //#TEST:
  {$if defined(_IDE_) and defined(_DEBUG_) and defined(_TEST_)}
  if Assigned(Result) then begin
    if (FEntries[i].EName = 'libssh2_init') then begin
      @_test_libssh2_init := Result;
      Result := @test_libssh2_init;
      FEntries[i].EProc := Result;
    end;
  end;
  {$ifend}
  //#TEST.
end;//*)

function TDll.DelayLoadIndex(Index: Integer): Pointer;
begin
  Result := GetProcAddrFromIndex(Index);
  if Assigned(Result)
  then FEntries[Index].EProc^ := Result
  else FEntries[Index].EProc^ := FEntries[Index].DProc;
end;

class procedure TDll.DoError(const Msg: string; Show: Boolean; Warn: Boolean);
{$IFDEF _MINI_}var uType: Cardinal;{$ENDIF}
begin
  {$IFDEF UNICODE}
  OutputDebugStringW(PWideChar(UnicodeString('ERROR: TDll: ' + Msg)));
  {$ELSE}
  OutputDebugStringA(PAnsiChar(AnsiString('ERROR: TDll: ' + Msg)));
  {$ENDIF}
  if IsConsole and Show then
  begin
    writeln('ERROR: ', Msg);
  end;
  {$IFNDEF _MINI_}
  if Show then
    raise EDllError.Create(Msg);
  {$ELSE  _MINI_}
  if Show then
  begin
    uType := MB_OK;
    if Warn
    then uType := uType or MB_ICONWARNING
    else uType := uType or MB_ICONERROR;
    {$IFDEF UNICODE}
    MessageBoxW(0, PWideChar(UnicodeString(Msg)), nil, uType);
    {$ELSE}
    MessageBoxA(0, PAnsiChar(AnsiString(Msg)), }nil, MB_ICONERROR);
    {$ENDIF}
    {$if declared(Abort)}
    //--raise EDllError.Create(Msg);
    Abort;
    {$else}
    Halt(1);
    {$ifend}
  end;
  {$ENDIF _MINI_}
end;

class procedure TDll.Error(const Msg: string);
begin
  TDll.DoError(Msg, {Show:}True, {Warn:}False);
end;

class procedure TDll.Warning(const Msg: string);
begin
  TDll.DoError(Msg, {Show:}False, {Warn:}True);
end;

function TDll.LoadHandle: HMODULE;
begin
  if FHandle = 0 then begin
    {$if declared(SafeLoadLibrary)}
    FHandle := SafeLoadLibrary(FullPath);
    {$else}
    FHandle := Windows.LoadLibrary(PChar(FullPath));
    {$ifend}
    if FHandle <> 0 then
      Dlls.DllNotify(Self, daLoadedDll, -1);
  end;
  Result := FHandle;
end;

{$IFDEF _MINI_}
{$hints off}
function SysErrorMessage(ErrorCode: Cardinal; AModuleHandle: THandle = 0): string;
var Len: Cardinal; Flags: DWORD;
  Buffer: {$IFDEF UNICODE}PWideChar{$ELSE}PAnsiChar{$ENDIF};
  U: {$IFDEF UNICODE}UnicodeString{$ELSE}AnsiString{$ENDIF};
begin
  Flags := FORMAT_MESSAGE_FROM_SYSTEM or
    FORMAT_MESSAGE_IGNORE_INSERTS or
    FORMAT_MESSAGE_ARGUMENT_ARRAY or
    FORMAT_MESSAGE_ALLOCATE_BUFFER;
  if AModuleHandle <> 0 then
    Flags := Flags or FORMAT_MESSAGE_FROM_HMODULE;
  //# Obtain the formatted message for the given Win32 ErrorCode
  //# Let the OS initialize the Buffer variable. Need to LocalFree it afterward.
  {$IFDEF UNICODE}
  Len := FormatMessageW(Flags, Pointer(AModuleHandle), ErrorCode, 0, @Buffer, 0, nil);
  {$ELSE}
  Len := FormatMessageA(Flags, Pointer(AModuleHandle), ErrorCode, 0, @Buffer, 0, nil);
  {$ENDIF};
  try
    //# Remove the undesired line breaks and '.' char
    {$IFDEF UNICODE}
    while (Len > 0) and ((Buffer[Len - 1] <= WideChar(#32)) or (Buffer[Len - 1] = WideChar('.'))) do begin
    {$ELSE}
    while (Len > 0) and ((Buffer[Len - 1] <= AnsiChar(#32)) or (Buffer[Len - 1] = AnsiChar('.'))) do begin
    {$ENDIF}
      Dec(Len);
    end;
    //# Convert to Delphi string
    SetString(U, Buffer, Len);
    Result := string(U);
  finally
    //# Free the OS allocated memory block
    LocalFree(HLOCAL(Buffer));
  end;
end;
{$hints on}
{$ENDIF _MINI_}

function TDll.GetHandle: HMODULE;
begin
  Result := FHandle;
  if Result = 0 then begin
    Result := LoadHandle();
    if Result = 0 then
      {$IFNDEF _MINI_}
      TDll.Error(Format(SCannotLoadLibrary, [FullPath, SysErrorMessage(GetLastError)]));
      {$ELSE}
      TDll.Error(
        'Could not find the library: "' + FullPath + '"'#13#10'(' + SysErrorMessage(GetLastError()) + ')'
      );
      {$ENDIF _MINI_}
  end;
end;

function TDll.GetIndexFromThunk(Thunk: PThunk): Integer;
begin
  //# We calculate the thunk index by subtracting the start of the array
  //# and dividing by the size of the array elements
  Result := (PAnsiChar(Thunk) - PAnsiChar(@FThunkingCode^.Thunks[0])) div SizeOf(TThunk);
end;

function TDll.LoadProcAddrFromIndex(Index: Integer; var Addr: Pointer): Boolean;
var H: HMODULE;
begin
  Result := ValidIndex(Index);
  if Result then begin
    H := GetHandle();
    Result := H <> 0;
    if Result then begin
      Addr := Windows.GetProcAddress(H, FEntries[Index].EName);
      Result := Assigned(Addr);
      if not Result then begin
        Addr := FEntries[Index].DProc;
        Result := Assigned(Addr);
      end;
      if Result then
        Dlls.DllNotify(Self, daLinkedRoutine, Index);
    end;
  end;
end;

function TDll.GetProcAddrFromIndex(Index: Integer): Pointer;
var OK: Boolean;
begin
  {-hints off}
  Result := nil;
  OK := LoadProcAddrFromIndex(Index, Result);
  if not OK then
  begin
    {$IFNDEF _MINI_}
    TDll.Error(Format(SCannotGetProcAddress, [EntryName[Index], FullPath, SysErrorMessage(GetLastError)]));
    {$ELSE}
    TDll.Error(
      'Could not find the routine "'+EntryName[Index]+'" in the library "'+FullPath+'"'#13#10'('+SysErrorMessage(GetLastError())+')'
    );
    {$ENDIF !_MINI_}
  end;
  {-hints on}
end;

function TDll.HasThunk(Thunk: PThunk): Boolean;
begin
  //# The thunk belongs to us if its address is in the thunk array
  Result := (PAnsiChar(Thunk) >= PAnsiChar(@FThunkingCode^.Thunks[0])) and
            (PAnsiChar(Thunk) <= PAnsiChar(@FThunkingCode^.Thunks[Count-1]));
end;

procedure TDll.Load;
var i : Integer;
begin
  FDllFinalize := False;
  for i := 0 to Count-1 do
    DelayLoadIndex(i);
end;

function AnsiCompareText(const S1, S2: string): Integer;
begin
  Result := CompareString(LOCALE_USER_DEFAULT, NORM_IGNORECASE or SORT_STRINGSORT, PChar(S1),
    Length(S1), PChar(S2), Length(S2)) - 2;
end;

function CompareText(const S1, S2: string): Integer;
begin
  Result := AnsiCompareText(S1, S2);
end;

procedure TDll.SetFullPath(const Value: string);
begin
  if CompareText(FFullPath, Value) <> 0 then begin
    Unload;
    FFullPath := Value;
    FShortName := AnsiLowerCase(ExtractFileName(FFullPath));
  end;
end;

function TDll.GetEntryName(Index: Integer): string;
begin
  if ValidIndex(Index) then
    Result := EntryToString(FEntries[Index])
  else begin
    {$IFNDEF _MINI_}
    Result := Format(SIndexOutOfRange, [Index]);
    {$ELSE}
    Result := SIndexOutOfRange + '(' + IntToStr(Index) + ')';
    {$ENDIF _MINI_}
  end;
end;

procedure TDll.ActivateThunks;
//# Patch the procedure variables to point to the generated thunks
var i : Integer; E: PEntryEx; T: PThunks; OK: Boolean;
begin
{
//# OLD:
  for i := 0 to Count-1 do
    if Assigned(FEntries[i].EProc) then
      FEntries[i].EProc^ := @FThunkingCode^.Thunks[i];
//# OLD.
}
//# NEW:
  if (Count = 0) or (FThunkingCode = nil) or (Length(FEntries) = 0) then
    Exit;
  E := @FEntries[0];
  //--T := @FThunkingCode^.Thunks[0]; //for i := Count-1 downto 0 do
  for i := 0 to Count-1 do begin
    if Assigned(E^.EProc) then begin //@dbg:  FEntries[i].EProc^  ;  FEntries[i]
      T := @FThunkingCode^.Thunks[i];
      if E^.EProc^ <> T then begin
        OK := (not FDllFinalize) or Dlls.CodeHeap.IsPtrWritable(E^.EProc);
        if not OK then begin
          TDll.DoError('"'+FShortName+'": "'+FEntries[i].EName+'" - Failed wrapper memory accessible', {Show:}False, {Warn:}False);
          OK := Dlls.CodeHeap.SetMemWritable(Pointer(E^.EProc), SizeOf(Pointer));
          if OK then
            TDll.Warning('"'+FShortName+'": "'+FEntries[i].EName+'" - Fixed memory attribute');
        end;
        if OK then begin
          try
            E^.EProc^ := T;
          except
            OK := False;
          end;
        end;
        if not OK then
          TDll.DoError('"'+FShortName+'": "'+FEntries[i].EName+'" - Failed wrapper memory access', {Show:}not FDllFinalize, {Warn:}False);
      end;
    end;
    Inc(E);
    //--Inc(T);
  end;
//# NEW.
end;

procedure TDll.Unload;
var ADllFinalize: Boolean;
begin
  if FHandle <> 0 then begin
    ADllFinalize := FDllFinalize;
    FDllFinalize := True;
    try
      ActivateThunks;
    finally
      FDllFinalize := ADllFinalize;
    end;
    //
    try
      FreeLibrary(FHandle);
    except
      on e: Exception do
        TDll.DoError('"'+FShortName+'": Failed unload library', {Show:}False, {Warn:}False);
    end;
    FHandle := 0;
    Dlls.DllNotify(Self, daUnloadedDll, -1);
  end;
end;

function TDll.ValidIndex(Index: Integer): Boolean;
begin
  Result := (Index >= 0) and (Index <= Count-1);
end;

function TDll.CheckIndex(Index: Integer): Boolean;
begin
  Result := ValidIndex(Index);
  if not Result then begin
    {$IFNDEF _MINI_}
    TDll.Error(Format(SIndexOutOfRange, [Index]));
    {$ELSE}
    TDll.Error(
      'DLL-entry index out of range ('+IntToStr(Index)+')'
    );
    {$ENDIF !_MINI_}
  end;
end;

function TDll.GetProcs(Index: Integer): Pointer;
begin
  if CheckIndex(Index)
  then Result := FEntries[Index].EProc^
  else Result := nil;
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
var E: PEntryEx;
begin
  if Assigned(Proc) then begin
    for Result := 0 to Count-1 do begin
      E := @FEntries[Result];
      if (E^.EProc = Proc) or (E^.DProc = Proc) then
        Exit;
    end;
  end;
  Result := -1;
end;

function TDll.HasRoutine(Proc: PPointer): Boolean;
begin
  Result := Assigned(Proc) and Available
    and ( (not HasThunk(Proc^))
          or LoadProcAddrFromIndex(
               GetIndexFromProc(Proc)
               ,Proc^
             )
   );
end;

function TDll.HookRoutine(Proc: PPointer; HookProc: Pointer; var OrgProc{: Pointer}): Boolean;
begin
  Result := HasRoutine(Proc);
  if Result then begin
    Pointer(OrgProc) := Proc^;
    Proc^            := HookProc;
  end;
end;

function TDll.UnHookRoutine(Proc: PPointer; var OrgProc{: Pointer}): Boolean;
begin
  Result := Assigned(Pointer(OrgProc));
  if Result then begin
    Proc^            := Pointer(OrgProc);
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
    Exit; //-TDll.Warning(Format(SListIndexError, [Index]));
  Dec(FCount);
  if Index < FCount then
    System.Move(FList^[Index + 1], FList^[Index], (FCount - Index) * SizeOf(Pointer));
end;

function TList.Get(Index: Integer): Pointer;
begin
  if (Index < 0) or (Index >= FCount)
  then Result := nil //-TDll.Warning(Format(SListIndexError, [Index]))
  else Result := FList^[Index];
end;

procedure TList.Grow;
var Delta: Integer;
begin
  if FCapacity > 64 then
    Delta := FCapacity div 4
  else
    if FCapacity > 8
    then Delta := 16
    else Delta := 4;
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
    Exit; //-TDll.Warning(Format(SListIndexError, [Index]));
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
    Exit; //-TDll.Warning(Format(SListCapacityError, [NewCapacity]));
  if NewCapacity <> FCapacity then begin
    ReallocMem(FList, NewCapacity * SizeOf(Pointer));
    FCapacity := NewCapacity;
  end;
end;

procedure TList.SetCount(NewCount: Integer);
var I: Integer;
begin
  if (NewCount < 0) or (NewCount > MaxListSize) then
    Exit; //-TDll.Warning(Format(SListCountError, [NewCount]));
  if NewCount > FCapacity then
    SetCapacity(NewCount);
  if NewCount > FCount then
    FillChar(FList^[FCount], (NewCount - FCount) * SizeOf(Pointer), 0)
  else for I := FCount - 1 downto NewCount do
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
var i: Integer; D: TDll; C: TCodeHeap;
begin
  for i := Count-1 downto 0 do begin
    D := TDll(Dlls[i]);
    if Assigned(D) then begin
      try
        D.FDllFinalize := True;
        D.Free;
      except
      end;
      //-if i < Count then
      //-  {$IFDEF _MINI_}FList^{$ELSE}List{$ENDIF}[i] := nil; // Put(i, nil);
    end;
  end;
  if Assigned(FCodeHeap) then begin
    C := FCodeHeap;
    FCodeHeap := nil;
    C.Free;
  end;
  //
  if Self = HVDll.Dlls then
    HVDll.Dlls := nil;
  //
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

procedure FInit;
begin
  if Assigned(Dlls) then begin
    try
      Dlls.FDllFinalize := True;
      Dlls.Free;
    except
    end;
    Dlls := nil;
  end;
end;
initialization
  Dlls := TDlls.Create;
finalization
  Finit;
{$ENDIF SUPPORTED}
end.
