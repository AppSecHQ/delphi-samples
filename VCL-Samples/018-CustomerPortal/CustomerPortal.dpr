program CustomerPortal;

uses
  Vcl.Forms,
  uMainForm in 'uMainForm.pas' {MainForm},
  uDatabaseModule in 'uDatabaseModule.pas' {DatabaseModule: TDataModule},
  uUserAuth in 'uUserAuth.pas',
  uFileManager in 'uFileManager.pas',
  uReportEngine in 'uReportEngine.pas',
  uApiClient in 'uApiClient.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TMainForm, MainForm);
  Application.CreateForm(TDatabaseModule, DatabaseModule);
  Application.Run;
end.
