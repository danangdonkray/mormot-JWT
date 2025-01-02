unit RestServer.U_Data;

interface
uses syncommons, Mormot;

Type
  TAuthUser = class(TSQLAuthUser)
  private
    FExternalID2: integer;
    FExternalID1: integer;
    FComplement: RawByteString;
  published
    property ExternalID1  : integer read FExternalID1  write FExternalID1;
    property ExternalID2  : integer read FExternalID2  write FExternalID2;
    property Complement   : RawByteString read FComplement write FComplement;
  end;

  TAuthUserClass = Class of TAuthUser;

function CreateSQLModel(const aRoot : RawUTF8; const Tables: array of TSQLRecordClass; const AuthUserRedefine : TAuthUserClass = nil) : TSQLModel;
function DTBModelBase(const aRoot : RawUTF8) : TSQLModel;

implementation

function CreateSQLModel(const aRoot : RawUTF8; const Tables: array of TSQLRecordClass;
  const AuthUserRedefine : TAuthUserClass) : TSQLModel;
const _SysTable : integer = 2;
var Tb : TSQLRecordClassDynArray;
    dy : TDynArray;
    i : integer;
begin
  SetLength(Tb, length(Tables) + _SysTable);
  if AuthUserRedefine <> nil then Tb[0] := AuthUserRedefine
  else Tb[0] := TAuthUser;
  Tb[1] := TSQLAuthGroup;

  for i := low(Tables) to High(Tables) do
    Tb[i + _SysTable] := Tables[i];

  result := TSQLModel.Create(Tb, aRoot);
end;

function DTBModelBase(const aRoot : RawUTF8) : TSQLModel;
begin
  Result := CreateSQLModel(aRoot,  [TAuthUser,
                                    TSQLAuthGroup]);
end;

end.
