{ HVHeaps.pas } // version: 2020.0615.1000
unit HVHeaps;
//
// https://github.com/pult/dll_load_delay
// https://bitbucket.org/VadimLV/dll_load_delay
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

{$IFDEF FPC}
  {.$WARNINGS OFF}
  {.$HINTS OFF}

  {$MODE OBJFPC}
  //{$MODE DELPHI}
  {$H+}
  {-DEFINE UNICODE}    { optional }

  {$B-,R-}
  {$Q-}
  {$J+}

  {$ASSERTIONS OFF}

  {$ALIGN 8} // For packed record
  {$MINENUMSIZE 1}
{$ELSE !FPC}
  {$IFDEF UNICODE}
    {$ALIGN 8} // For packed record
    {$MINENUMSIZE 1}

    //{$IF CompilerVersion >= 25.00}{XE4Up}
    //  {$ZEROBASEDSTRINGS OFF}
    //{$IFEND}
  {$ENDIF}
  {.$WARN UNSAFE_CODE OFF}
  {.$WARN UNSAFE_TYPE OFF}
  {.$WARN UNSAFE_CAST OFF}
{$ENDIF !FPC}

uses
  Windows
  {$IFNDEF FPC}
  ,Types
  {$ENDIF !FPC}
  ;

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
    function GetMem(var P{: Pointer}; Size: DWORD): Boolean; virtual;
    function FreeMem(P: Pointer): Boolean;
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
    function GetMem(var P{: Pointer}; Size: DWORD): Boolean; override;
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
  Pointer(P) := Windows.HeapAlloc(Handle, FAllocationFlags, Size);
  Result := Pointer(P) <> nil;
end;

function TPrivateHeap.SizeOfMem(P: Pointer): DWORD;
begin
  Result := Windows.HeapSize(Handle, 0, P);
  // HeapSize does not set GetLastError, but returns $FFFFFFFF if it fails
  if Result = $FFFFFFFF then
    Result := 0;
end;

{ TCodeHeap }

function TCodeHeap.GetMem(var P{: Pointer}; Size: DWORD): Boolean;
var
  Dummy: DWORD;
begin
  Result := inherited GetMem(P, Size);
  if Result then
    Result := Windows.VirtualProtect(Pointer(P), Size, PAGE_EXECUTE_READWRITE, @Dummy);
end;

initialization
{$ENDIF MSWINDOWS}
end.
