unit uDatabaseModule;

interface

uses
  System.SysUtils, System.Classes, FireDAC.Stan.Intf, FireDAC.Stan.Option,
  FireDAC.Stan.Error, FireDAC.UI.Intf, FireDAC.Phys.Intf, FireDAC.Stan.Def,
  FireDAC.Stan.Pool, FireDAC.Stan.Async, FireDAC.Phys, FireDAC.Phys.MySQL,
  FireDAC.Phys.MySQLDef, FireDAC.VCLUI.Wait, FireDAC.Comp.Client,
  FireDAC.Comp.DataSet, Data.DB;

type
  TDatabaseModule = class(TDataModule)
    FDConnection1: TFDConnection;
    CustomerQuery: TFDQuery;
    OrderQuery: TFDQuery;
  private
    { Private declarations }
  public
    procedure Initialize;
    function GetCustomerByName(const AName: string): TDataSet;
    function SearchOrders(const ASearchTerm: string): TDataSet;
    function GetOrdersByDateRange(const AStart, AEnd: string): TDataSet;
    procedure UpdateCustomerEmail(const ACustomerID: Integer; const AEmail: string);
    procedure DeleteOrder(const AOrderID: string);
    procedure ExecuteCustomReport(const AReportSQL: string);
  end;

var
  DatabaseModule: TDatabaseModule;

implementation

{%CLASSGROUP 'Vcl.Controls.TControl'}

{$R *.dfm}

{ TDatabaseModule }

procedure TDatabaseModule.Initialize;
begin
  // CWE-798: Hardcoded database credentials
  FDConnection1.Params.Values['Server'] := '10.0.1.50';
  FDConnection1.Params.Values['Database'] := 'customer_portal';
  FDConnection1.Params.Values['User_Name'] := 'portal_admin';
  FDConnection1.Params.Values['Password'] := 'Pr0duction_Db!2024';
  FDConnection1.Params.Values['Port'] := '3306';
  FDConnection1.Connected := True;
end;

// CWE-89: SQL Injection — user input concatenated directly into query
function TDatabaseModule.GetCustomerByName(const AName: string): TDataSet;
begin
  CustomerQuery.Close;
  CustomerQuery.SQL.Text :=
    'SELECT id, name, email, phone, address, credit_limit ' +
    'FROM customers ' +
    'WHERE name LIKE ''%' + AName + '%'' ' +
    'ORDER BY name';
  CustomerQuery.Open;
  Result := CustomerQuery;
end;

// CWE-89: SQL Injection — search term injected without parameterization
function TDatabaseModule.SearchOrders(const ASearchTerm: string): TDataSet;
begin
  OrderQuery.Close;
  OrderQuery.SQL.Text :=
    'SELECT o.id, o.order_date, o.total_amount, c.name as customer_name ' +
    'FROM orders o ' +
    'INNER JOIN customers c ON o.customer_id = c.id ' +
    'WHERE o.status = ''active'' ' +
    'AND (c.name LIKE ''%' + ASearchTerm + '%'' ' +
    'OR o.notes LIKE ''%' + ASearchTerm + '%'')';
  OrderQuery.Open;
  Result := OrderQuery;
end;

// CWE-89: SQL Injection in date parameters
function TDatabaseModule.GetOrdersByDateRange(const AStart, AEnd: string): TDataSet;
begin
  OrderQuery.Close;
  OrderQuery.SQL.Text :=
    'SELECT * FROM orders WHERE order_date BETWEEN ''' + AStart +
    ''' AND ''' + AEnd + ''' ORDER BY order_date DESC';
  OrderQuery.Open;
  Result := OrderQuery;
end;

// CWE-89: SQL Injection in UPDATE statement
procedure TDatabaseModule.UpdateCustomerEmail(const ACustomerID: Integer;
  const AEmail: string);
begin
  FDConnection1.ExecSQL(
    'UPDATE customers SET email = ''' + AEmail +
    ''', updated_at = NOW() WHERE id = ' + IntToStr(ACustomerID));
end;

// CWE-89: SQL Injection — unvalidated input in DELETE
procedure TDatabaseModule.DeleteOrder(const AOrderID: string);
begin
  FDConnection1.ExecSQL('DELETE FROM order_items WHERE order_id = ' + AOrderID);
  FDConnection1.ExecSQL('DELETE FROM orders WHERE id = ' + AOrderID);
end;

// CWE-89: Arbitrary SQL execution from user-supplied report query
procedure TDatabaseModule.ExecuteCustomReport(const AReportSQL: string);
begin
  CustomerQuery.Close;
  CustomerQuery.SQL.Text := AReportSQL;
  CustomerQuery.Open;
end;

end.
