unit uFileManager;

interface

uses
  System.SysUtils, System.Classes, System.IOUtils, Vcl.Dialogs,
  Winapi.ShellAPI, Winapi.Windows;

type
  TFileManager = class
  private
    FBaseUploadPath: string;
    FBaseTempPath: string;
  public
    constructor Create;

    function ReadCustomerDocument(const ACustomerID: Integer;
      const AFileName: string): TBytes;
    procedure SaveUploadedFile(const ACustomerID: Integer;
      const AFileName: string; const AContent: TBytes);
    procedure ExportReport(const AFormat, AOutputPath: string);
    procedure OpenDocument(const AFilePath: string);
    procedure ProcessBatchFile(const ACommandFile: string);
    function GetDocumentList(const APath: string): TStringList;
    procedure CleanupTempFiles(const APattern: string);
  end;

implementation

constructor TFileManager.Create;
begin
  inherited;
  FBaseUploadPath := 'C:\CustomerPortal\Uploads\';
  FBaseTempPath := 'C:\CustomerPortal\Temp\';
end;

// CWE-22: Path Traversal — filename not sanitized, allows ../../ sequences
function TFileManager.ReadCustomerDocument(const ACustomerID: Integer;
  const AFileName: string): TBytes;
var
  FullPath: string;
begin
  // Attacker can use AFileName = '../../etc/passwd' or '..\..\windows\system32\config\sam'
  FullPath := FBaseUploadPath + IntToStr(ACustomerID) + '\' + AFileName;
  Result := TFile.ReadAllBytes(FullPath);
end;

// CWE-22: Path Traversal in file upload
// CWE-434: Unrestricted Upload of File with Dangerous Type — no extension validation
procedure TFileManager.SaveUploadedFile(const ACustomerID: Integer;
  const AFileName: string; const AContent: TBytes);
var
  FullPath: string;
  FileStream: TFileStream;
begin
  // No validation on filename — allows path traversal and arbitrary file types
  FullPath := FBaseUploadPath + IntToStr(ACustomerID) + '\' + AFileName;
  ForceDirectories(ExtractFilePath(FullPath));

  FileStream := TFileStream.Create(FullPath, fmCreate);
  try
    FileStream.WriteBuffer(AContent[0], Length(AContent));
  finally
    FileStream.Free;
  end;
end;

// CWE-78: OS Command Injection — user input passed to shell command
procedure TFileManager.ExportReport(const AFormat, AOutputPath: string);
var
  CmdLine: string;
begin
  // AFormat and AOutputPath come from user input, injected into command
  CmdLine := 'cmd.exe /c wkhtmltopdf --format ' + AFormat +
    ' "C:\CustomerPortal\Reports\template.html" "' + AOutputPath + '"';
  WinExec(PAnsiChar(AnsiString(CmdLine)), SW_HIDE);
end;

// CWE-78: OS Command Injection via ShellExecute
procedure TFileManager.OpenDocument(const AFilePath: string);
begin
  // User-controlled path passed directly to ShellExecute
  ShellExecute(0, 'open', PChar(AFilePath), nil, nil, SW_SHOWNORMAL);
end;

// CWE-78: Command Injection — reading and executing commands from a file
procedure TFileManager.ProcessBatchFile(const ACommandFile: string);
var
  Commands: TStringList;
  i: Integer;
begin
  Commands := TStringList.Create;
  try
    Commands.LoadFromFile(ACommandFile);
    for i := 0 to Commands.Count - 1 do
    begin
      // Each line executed as a shell command
      WinExec(PAnsiChar(AnsiString(Commands[i])), SW_HIDE);
    end;
  finally
    Commands.Free;
  end;
end;

// CWE-22: Directory listing with path traversal
function TFileManager.GetDocumentList(const APath: string): TStringList;
var
  Files: TStringDynArray;
  i: Integer;
begin
  Result := TStringList.Create;
  // APath can include ../ sequences to list arbitrary directories
  Files := TDirectory.GetFiles(FBaseUploadPath + APath);
  for i := 0 to Length(Files) - 1 do
    Result.Add(Files[i]);
end;

// CWE-78: OS Command Injection in cleanup routine
procedure TFileManager.CleanupTempFiles(const APattern: string);
var
  CmdLine: string;
begin
  // APattern injected into del command without sanitization
  CmdLine := 'cmd.exe /c del /q "' + FBaseTempPath + APattern + '"';
  WinExec(PAnsiChar(AnsiString(CmdLine)), SW_HIDE);
end;

end.
