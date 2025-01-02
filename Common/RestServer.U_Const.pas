unit RestServer.U_Const;

interface

const
  /// THttpRequest timeout default value for remote connection
  // - default is 90 seconds
  EIG_HTTP_DEFAULT_CONNECTTIMEOUT: integer = 90000;
  /// THttpRequest timeout default value for data sending
  // - default is 60 seconds
  EIG_HTTP_DEFAULT_SENDTIMEOUT: integer = 60000;
  /// THttpRequest timeout default value for data receiving
  // - default is 1 hour
  EIG_HTTP_DEFAULT_RECEIVETIMEOUT: integer = 3600000;

  CONNECTION_TIMEOUT  = 3000;

implementation

end.
