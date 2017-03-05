unit HVHeaps;
//
// https://github.com/pult/dll_load_delay
// http://hallvards.blogspot.com/2008/03/tdm8-delayloading-of-dlls.html
//
// Simple wrapper classes around the Win32 Heap functions.
// Written by Hallvard Vassbotn (hallvard@falcon.no), January 1999
//
interface

{$IFDEF WIN32}
  {$DEFINE MSWINDOWS}
{$ENDIF}
{$IFDEF WIN64}
  {$DEFINE MSWINDOWS}
{$ENDIF}

{$IFDEF MSWINDOWS}

uses
  Windows, Types;

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

type
  // The TPrivateHeap class gives basic memory allocation capability
  // The benefit of using this class instead of the native GetMem
  // and FreeMem routines, is that the memory pages used will
  // be seperate from other allocations. This gives reduced
  // fragmentation.
  TPrivateHeap = class//(TObject)
  private
    FHandle: THandle;
    FAllocationFlags: DWORD;
    function GetHandle: THandle;
  public
    destructor Destroy; override;
    procedure GetMem(var P{: Pointer}; Size: DWORD); virtual;
    procedure FreeMem(P: Pointer);
    function SizeOfMem(P: Pointer): DWORD;
    property Handle: THandle read GetHandle;
    property AllocationFlags: DWORD read FAllocationFlags write FAllocationFlags;
  end;

  // The Code Heap adds the feature of allocating readable/writable
  // and executable memory blocks. This allows us to have safe
  // run-time generated code while not wasting as much memory
  // as calls to VirtualAlloc would have caused, while avoiding
  // the pitfalls of changing the protection flags of blocks
  // allocated with GetMem.
  TCodeHeap = class(TPrivateHeap)
  public
    procedure GetMem(var P{: Pointer}; Size: DWORD); override;
  end;

{$ENDIF MSWINDOWS}

implementation

{$IFDEF MSWINDOWS}

uses
  //{$IFDEF VER93} // Delphi2
  //D2Support,
  //{$ENDIF}
  SysUtils;

function Win32Handle(Handle: THandle): THandle;
begin
  if Handle = 0 then
    //RaiseLastWin32Error;
    RaiseLastOsError;
  Result := Handle;
end;

function Win32Pointer(P: Pointer): Pointer;
begin
  if P = nil then
    //RaiseLastWin32Error;
    RaiseLastOsError;
  Result := P;
end;

{ TPrivateHeap }

destructor TPrivateHeap.Destroy;
begin
  if FHandle <> 0 then
  begin
    Win32Check(Windows.HeapDestroy(FHandle));
    FHandle := 0;
  end;
  inherited Destroy;
end;

procedure TPrivateHeap.FreeMem(P: Pointer);
begin
  Win32Check(Windows.HeapFree(Handle, 0, P));
end;

function TPrivateHeap.GetHandle: THandle;
begin
  if FHandle = 0 then
    FHandle := Win32Handle(Windows.HeapCreate(0, 0, 0));
  Result := FHandle;
end;

procedure TPrivateHeap.GetMem(var P{: Pointer}; Size: DWORD);
begin
  Pointer(P) := Win32Pointer(Windows.HeapAlloc(Handle, AllocationFlags, Size));
end;

function TPrivateHeap.SizeOfMem(P: Pointer): DWORD;
begin
  Result := Windows.HeapSize(Handle, 0, P);
  // HeapSize does not set GetLastError, but returns $FFFFFFFF if it fails
  if Result = $FFFFFFFF then
    Result := 0;
end;

{ TCodeHeap }

procedure TCodeHeap.GetMem(var P{: Pointer}; Size: DWORD);
var
  Dummy: DWORD;
begin
  inherited GetMem(P, Size);
  Win32Check(Windows.VirtualProtect(Pointer(P), Size, PAGE_EXECUTE_READWRITE, @Dummy));
end;

initialization
{$ENDIF MSWINDOWS}
end.
