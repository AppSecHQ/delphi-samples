unit uMainForm;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs,
  Vcl.StdCtrls, Vcl.Grids, Vcl.DBGrids, Data.DB, Vcl.ExtCtrls,
  Vcl.ComCtrls;

type
  TMainForm = class(TForm)
    PageControl1: TPageControl;
    tsCustomers: TTabSheet;
    tsOrders: TTabSheet;
    tsReports: TTabSheet;
    tsFiles: TTabSheet;
    edtSearch: TEdit;
    btnSearch: TButton;
    dbgCustomers: TDBGrid;
    dbgOrders: TDBGrid;
    edtReportSQL: TMemo;
    btnRunReport: TButton;
    edtUploadPath: TEdit;
    btnUpload: TButton;
    btnExport: TButton;
    edtExportFormat: TComboBox;
    edtExportPath: TEdit;
    edtUsername: TEdit;
    edtPassword: TEdit;
    btnLogin: TButton;
    lblStatus: TLabel;
    edtWebhookUrl: TEdit;
    btnTestWebhook: TButton;
    procedure btnSearchClick(Sender: TObject);
    procedure btnRunReportClick(Sender: TObject);
    procedure btnUploadClick(Sender: TObject);
    procedure btnExportClick(Sender: TObject);
    procedure btnLoginClick(Sender: TObject);
    procedure btnTestWebhookClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  MainForm: TMainForm;

implementation

uses
  uDatabaseModule, uUserAuth, uFileManager, uReportEngine, uApiClient;

{$R *.dfm}

var
  Auth: TUserAuth;
  FileMgr: TFileManager;
  ReportEng: TReportEngine;
  ApiCli: TApiClient;

procedure TMainForm.FormCreate(Sender: TObject);
begin
  DatabaseModule.Initialize;
  Auth := TUserAuth.Create(DatabaseModule.FDConnection1);
  FileMgr := TFileManager.Create;
  ReportEng := TReportEngine.Create(DatabaseModule.FDConnection1);
  ApiCli := TApiClient.Create;
end;

// User search input goes directly to SQL query — SQL Injection entry point
procedure TMainForm.btnSearchClick(Sender: TObject);
begin
  DatabaseModule.GetCustomerByName(edtSearch.Text);
end;

// User-supplied SQL executed directly — arbitrary query execution
procedure TMainForm.btnRunReportClick(Sender: TObject);
begin
  DatabaseModule.ExecuteCustomReport(edtReportSQL.Text);
end;

// Upload with user-controlled filename — path traversal entry point
procedure TMainForm.btnUploadClick(Sender: TObject);
var
  FileContent: TBytes;
begin
  if FileExists(edtUploadPath.Text) then
  begin
    FileContent := TFile.ReadAllBytes(edtUploadPath.Text);
    FileMgr.SaveUploadedFile(Auth.CurrentUserID,
      ExtractFileName(edtUploadPath.Text), FileContent);
  end;
end;

// User-controlled format and path — command injection entry point
procedure TMainForm.btnExportClick(Sender: TObject);
begin
  FileMgr.ExportReport(edtExportFormat.Text, edtExportPath.Text);
end;

// Login with no rate limiting or input validation
procedure TMainForm.btnLoginClick(Sender: TObject);
begin
  if Auth.Authenticate(edtUsername.Text, edtPassword.Text) then
    lblStatus.Caption := 'Welcome, ' + edtUsername.Text
  else
    lblStatus.Caption := 'Login failed for: ' + edtUsername.Text;
end;

// SSRF entry point — user-controlled webhook URL
procedure TMainForm.btnTestWebhookClick(Sender: TObject);
begin
  ReportEng.SendWebhookNotification(edtWebhookUrl.Text,
    '{"test": "webhook connectivity check"}');
end;

end.
