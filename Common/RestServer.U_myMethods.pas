unit RestServer.U_myMethods;

interface
uses
  SynCommons,
  mOrmot,
  RestServer.I_RestInterface,
  myServer.U_RESTServer,
  RestServer.U_DTB;

type
  TmyMethods = class(TInterfacedObject, IInterface)
  private
    FLocker: TSynLocker;
  public
    procedure FreeInstance(); override;
    class function NewInstance(): TObject; override;
  published
    function HelloWorld():string;
    function SUM(a,b:Integer):string;
    function FullList : TServiceCustomAnswer;

    //request body json
    function tesjson(const data : RawJSON) : string;
  end;

implementation

{ TSample }

procedure TmyMethods.FreeInstance;
begin
  FLocker.Done();
  inherited FreeInstance();
end;

function TmyMethods.FullList: TServiceCustomAnswer;
var L : TSQLTableJSON;
    tmp : variant;
begin
  FLocker.Lock();
  try
    Result.Header := JSON_CONTENT_TYPE_HEADER;
    L := MainServer.RestServer.ExecuteList([TSampleData], 'SELECT * FROM SAMPLEDATA LIMIT 100');
    if Assigned(L) then begin
      tmp := _Arr([]);
      L.ToDocVariant(tmp, true);
      Result.Content := tmp;
      L.Free;
    end;
    Result.Status := HTTP_SUCCESS;
  finally
    FLocker.UnLock();
  end;
end;

function TmyMethods.HelloWorld: string;
begin
  Result:='hello world';
end;

class function TmyMethods.NewInstance: TObject;
begin
  Result := inherited NewInstance();
  TmyMethods(Result).FLocker.Init();
end;

function TmyMethods.SUM(a, b: Integer): string;
begin
   Result:=IntToString(a+b);
end;

function TmyMethods.tesjson(const data: RawJSON): string;
var jsoValue:Variant;
begin
  //sample json
  //{"Nama": "Danang","GraduationYear":2018} atau req body --> [{"Nama": "Danang","GraduationYear":2018}]

  jsoValue := _Json(data);
  Result:=jsoValue.Nama;
end;

end.
