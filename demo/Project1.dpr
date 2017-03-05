program Project1;

{$i app_linker.inc}

uses
  Forms,

  {$IFDEF UNICODE}{$IFNDEF FPC}
  uFxtDelayedHandler in '..\uFxtDelayedHandler.pas',
  {$ENDIF}{$ENDIF}

  libssh2 in '..\libssh2.pas',
  libssh2_publickey in '..\libssh2_publickey.pas',
  libssh2_sftp in '..\libssh2_sftp.pas',
  uMySFTPClient in '..\comp\uMySFTPClient.pas',

  Unit3 in 'Unit3.pas' {Form3},
  Unit4 in 'Unit4.pas' {FrmProgress};

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm3, Form3);
  Application.Run;
end.
