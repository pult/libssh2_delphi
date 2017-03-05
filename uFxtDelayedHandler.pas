// Failure load library by "delayed" : addeed exception information
// http://docwiki.embarcadero.com/Libraries/XE6/en/SysInit.SetDliFailureHook2
// http://docwiki.embarcadero.com/CodeExamples/XE6/en/DelayedLoading_%28Delphi%29
// http://www.drbob42.com/examines/examinc1.htm
//
// sample: function func_add(x,y: double): double; overload; stdcall
//             external 'sample.dll' name 'func_add_float' delayed;
//
unit uFxtDelayedHandler;

interface

{$IF CompilerVersion >= 21.00}
uses
  SysUtils;

type
  ELoadLibrary = class(Exception);
  EGetProcAddress = class(Exception);
{$IFEND}

implementation

{$IF CompilerVersion >= 21.00}

var
  LOldFailureHook: TDelayedLoadHook;

function DelayedHandlerHook(dliNotify: dliNotification; pdli: PDelayLoadInfo): Pointer; stdcall;
var
  S: string;
begin
  if dliNotify = dliFailLoadLibrary then
  begin
    raise ELoadLibrary.Create('Could not load library "' + string(pdli.szDll) + '"');
  end
  else if dliNotify = dliFailGetProcAddress then
  begin
    if pdli.dlp.fImportByName then
    begin
      S := '"' + string(pdli.dlp.szProcName) + '"';
    end
    else
    begin
      S := 'index ' + IntToStr(pdli.dlp.dwOrdinal);
    end;
    S := 'Could not load function ' + S + ' from library "' + string(pdli.szDll) + '"';
    raise EGetProcAddress.Create(S);
  end;

  if Assigned(LOldFailureHook) then
    Result := LOldFailureHook(dliNotify, pdli)
  else
    Result := nil;
end;

initialization
  {$IF CompilerVersion >= 24.00}
  LOldFailureHook := SetDliFailureHook2(DelayedHandlerHook);
  {$ELSE}
  LOldFailureHook := SetDliFailureHook(DelayedHandlerHook);
  {$IFEND}

finalization
  {$IF CompilerVersion >= 24.00}
  SetDliFailureHook2(LOldFailureHook);
  {$ELSE}
  SetDliFailureHook(LOldFailureHook);
  {$IFEND}

{$IFEND IF CompilerVersion >= 21.00}
end.
