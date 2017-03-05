unit Unit4;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ComCtrls;

type
  TFrmProgress = class(TForm)
    ProgressBar1: TProgressBar;
    Button1: TButton;
    Label1: TLabel;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FrmProgress: TFrmProgress;

implementation

{$R *.dfm}

procedure TFrmProgress.Button1Click(Sender: TObject);
begin
  ModalResult := mrCancel;
end;

end.
