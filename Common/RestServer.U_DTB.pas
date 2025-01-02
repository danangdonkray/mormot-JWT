unit RestServer.U_DTB;

interface
uses
  SynCommons,
  Mormot,
  RestServer.U_Data;

type
  TFirstName = RawUTF8;
  TLastName  = RawUTF8;

  TSampleData = class(TSQLRecord)
  private
    FFirstName: TFirstName;
    FLastName: TLastName;
  published
    property FirstName : TFirstName read FFirstName write FFirstName;
    property LastName : TLastName read FLastName write FLastName;
  end;

function DTBModel(const ARoot: RawUTF8): TSQLModel;

implementation

function DTBModel(const ARoot: RawUTF8): TSQLModel;
begin
  Result := CreateSQLModel(ARoot, [TSampleData]);
end;

end.
