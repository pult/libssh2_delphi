{ HVHeaps.pas } //# version: 2024.0117.0600
unit HVHeaps;
//#....
//# https://github.com/pult/dll_load_delay
//# https://bitbucket.org/VadimLV/dll_load_delay
//# http://hallvards.blogspot.com/2008/03/tdm8-delayloading-of-dlls.html
//#
//# Simple wrapper classes around the Win32 Heap functions.
//# Written by Hallvard Vassbotn (hallvard@falcon.no), January 1999
//#
interface

{$IFDEF WIN32}
  {$DEFINE MSWINDOWS}
{$ENDIF}
{$IFDEF WIN64}
  {$DEFINE MSWINDOWS}
{$ENDIF}

{$IFDEF MSWINDOWS}

{$undef allow_inline} { no change }
{$define allow_inline} { optional }

{$IFDEF  FPC}
  {-WARNINGS OFF}
  {-HINTS OFF}

  {$MODE OBJFPC}
  {-MODE DELPHI}
  {$H+}
  {-DEFINE UNICODE} { optional }

  {$B-,R-}
  {$Q-}
  {$J+}

  {$ASSERTIONS OFF}

  {$ALIGN 8} //# For packed record
  {$MINENUMSIZE 1}
{$ELSE  !FPC}
  {$IFDEF UNICODE}
    {$ALIGN 8} //# For packed record
    {$MINENUMSIZE 1}

  {$ENDIF}
  {-WARN UNSAFE_CODE OFF}
  {-WARN UNSAFE_TYPE OFF}
  {-WARN UNSAFE_CAST OFF}

  {$IFDEF CONDITIONALEXPRESSIONS}
    {$IF CompilerVersion >= 25.00} //# XE4_UP
      {$undef allow_inline} { no change }
    {$ELSE}
    {$IFEND}
  {$ELSE}
    {$undef allow_inline} { no change }
  {$ENDIF}

{$ENDIF !FPC}

uses
  Windows
  {$IFNDEF FPC}
  ,Types
  {$ENDIF !FPC}
  ;

type
  //# The TPrivateHeap class gives basic memory allocation capability
  //# The benefit of using this class instead of the native GetMem
  //# and FreeMem routines, is that the memory pages used will
  //# be seperate from other allocations. This gives reduced
  //# fragmentation.
  TPrivateHeap = class
  private
    FHandle: THandle;
    FAllocationFlags: DWORD;
    function GetHandle: THandle;
  public
    destructor Destroy; override;

    function GetMem(var P{: Pointer}; Size: DWORD): Boolean; virtual;
    function FreeMem(P: Pointer): Boolean; {$ifdef allow_inline}inline;{$endif}
    function SizeOfMem(P: Pointer): DWORD; {$ifdef allow_inline}inline;{$endif}
    class function IsMemWritable(P: Pointer; Size: DWORD): Boolean;
    class function IsPtrWritable(P: Pointer): Boolean; {$ifdef allow_inline}inline;{$endif}
    class function SetMemFlags(P: Pointer; Size: DWORD; MemProtectFlags: DWORD): Boolean;
    class function SetMemWritable(P: Pointer; Size: DWORD): Boolean;

    property Handle: THandle read GetHandle;
    property AllocationFlags: DWORD read FAllocationFlags write FAllocationFlags;
  end;

  //# The Code Heap adds the feature of allocating readable/writable
  //# and executable memory blocks. This allows us to have safe
  //# run-time generated code while not wasting as much memory
  //# as calls to VirtualAlloc would have caused, while avoiding
  //# the pitfalls of changing the protection flags of blocks
  //# allocated with GetMem.
  TCodeHeap = class(TPrivateHeap)
  public
    function GetMem(var P{: Pointer}; Size: DWORD): Boolean; override;
    class function SetMemWritable(P: Pointer; Size: DWORD): Boolean;
  end;

{$ENDIF MSWINDOWS}

implementation

{$IFDEF MSWINDOWS}

{ TPrivateHeap }

destructor TPrivateHeap.Destroy;
begin
  if FHandle <> 0 then
  begin
    Windows.HeapDestroy(FHandle);
    FHandle := 0;
  end;
  inherited;
end;

function TPrivateHeap.FreeMem(P: Pointer): Boolean;
begin
  Result := Windows.HeapFree(Handle, 0, P)
end;

function TPrivateHeap.GetHandle: THandle;
begin
  if FHandle = 0 then
    FHandle := Windows.HeapCreate(0, 0, 0);
  Result := FHandle;
end;

function TPrivateHeap.GetMem(var P{: Pointer}; Size: DWORD): Boolean;
begin
  if Pointer(@P) <> nil then
  begin
    Pointer(P) := Windows.HeapAlloc(Handle, FAllocationFlags, Size);
    Result := Pointer(P) <> nil;
  end
  else
    Result := False;
end;

function TPrivateHeap.SizeOfMem(P: Pointer): DWORD;
begin
  Result := Windows.HeapSize(Handle, 0, P);
  //# HeapSize does not set GetLastError, but returns $FFFFFFFF if it fails
  if Result = $FFFFFFFF then
    Result := 0;
end;

class function TPrivateHeap.IsMemWritable(P: Pointer; Size: DWORD): Boolean;
const
  PAGE_WRITABLE = PAGE_EXECUTE_WRITECOPY or PAGE_EXECUTE_READWRITE or
                  PAGE_READWRITE or PAGE_WRITECOPY;
var
  mbi: TMemoryBasicInformation;
  OK: Boolean;
begin
  Result := False;
  if P = nil then
    exit;
  OK := VirtualQuery(P, mbi, SizeOf(mbi)) = 0;
  if OK then
    exit;
  OK := (mbi.Protect = PAGE_NOACCESS) or ((mbi.Protect and PAGE_WRITABLE)= 0);
  if OK then
    exit;
  if P <> mbi.BaseAddress then
    Inc(Size, NativeUInt(P) - NativeUInt(mbi.BaseAddress) );
  Result := (Size <= mbi.RegionSize);
  if Result then
    exit;
  while True do //# search bad write block
  begin
    OK := (mbi.Protect = PAGE_NOACCESS) or ((mbi.Protect and PAGE_WRITABLE)= 0);
    if OK then
      exit;
    OK := (Size <= mbi.RegionSize);
    if OK then
      break;
    Dec(Size, mbi.RegionSize);
    //# Seek Ptr to next region:
    P := Pointer(NativeUInt(mbi.BaseAddress) + mbi.RegionSize + 1);
    OK := VirtualQuery(P, mbi, SizeOf(mbi)) = 0;
    if OK then
      exit;
  end;
  Result := True;
end;

class function TPrivateHeap.IsPtrWritable(P: Pointer): Boolean;
begin
  Result := Assigned(P) and IsMemWritable(P, SizeOf(Pointer));
end;

class function TPrivateHeap.SetMemFlags(P: Pointer; Size: DWORD; MemProtectFlags: DWORD): Boolean;
var
  Dummy: DWORD;
begin
  Result := Assigned(P);
  if Result then
    Result := Windows.VirtualProtect(P, Size, MemProtectFlags, @Dummy);
end;

class function TPrivateHeap.SetMemWritable(P: Pointer; Size: DWORD): Boolean;
begin
  Result := Assigned(P);
  if Result then
    Result := SetMemFlags(P, Size, PAGE_READWRITE);
end;

{ TCodeHeap }

function TCodeHeap.GetMem(var P{: Pointer}; Size: DWORD): Boolean;
begin
  Result := inherited GetMem(P, Size);
  if Result then
    Result := SetMemFlags(Pointer(P), Size, PAGE_EXECUTE_READWRITE);
end;

class function TCodeHeap.SetMemWritable(P: Pointer; Size: DWORD): Boolean;
begin
  Result := Assigned(P);
  if Result then
    Result := SetMemFlags(P, Size, PAGE_EXECUTE_READWRITE);
end;

initialization
{$ENDIF MSWINDOWS}
end.
