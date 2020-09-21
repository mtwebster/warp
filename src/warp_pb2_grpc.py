# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import warp_pb2 as warp__pb2


class WarpStub(object):
  """************ Important! ***************

  If you change anything here, you *must* run 'generate-protobuf' to update the
  generated stub files.

  Never change the existing members and member values of messages, only add new ones.

  """

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.CheckDuplexConnection = channel.unary_unary(
        '/Warp/CheckDuplexConnection',
        request_serializer=warp__pb2.LookupName.SerializeToString,
        response_deserializer=warp__pb2.HaveDuplex.FromString,
        )
    self.WaitForDuplexConnection = channel.unary_unary(
        '/Warp/WaitForDuplexConnection',
        request_serializer=warp__pb2.LookupName.SerializeToString,
        response_deserializer=warp__pb2.HaveDuplex.FromString,
        )
    self.GetRemoteMachineInfo = channel.unary_unary(
        '/Warp/GetRemoteMachineInfo',
        request_serializer=warp__pb2.LookupName.SerializeToString,
        response_deserializer=warp__pb2.RemoteMachineInfo.FromString,
        )
    self.GetRemoteMachineAvatar = channel.unary_stream(
        '/Warp/GetRemoteMachineAvatar',
        request_serializer=warp__pb2.LookupName.SerializeToString,
        response_deserializer=warp__pb2.RemoteMachineAvatar.FromString,
        )
    self.ProcessTransferOpRequest = channel.unary_unary(
        '/Warp/ProcessTransferOpRequest',
        request_serializer=warp__pb2.TransferOpRequest.SerializeToString,
        response_deserializer=warp__pb2.VoidType.FromString,
        )
    self.PauseTransferOp = channel.unary_unary(
        '/Warp/PauseTransferOp',
        request_serializer=warp__pb2.OpInfo.SerializeToString,
        response_deserializer=warp__pb2.VoidType.FromString,
        )
    self.AcceptTransferOpRequest = channel.unary_unary(
        '/Warp/AcceptTransferOpRequest',
        request_serializer=warp__pb2.OpInfo.SerializeToString,
        response_deserializer=warp__pb2.VoidType.FromString,
        )
    self.StartTransfer = channel.unary_stream(
        '/Warp/StartTransfer',
        request_serializer=warp__pb2.OpInfo.SerializeToString,
        response_deserializer=warp__pb2.FileChunk.FromString,
        )
    self.CancelTransferOpRequest = channel.unary_unary(
        '/Warp/CancelTransferOpRequest',
        request_serializer=warp__pb2.OpInfo.SerializeToString,
        response_deserializer=warp__pb2.VoidType.FromString,
        )
    self.StopTransfer = channel.unary_unary(
        '/Warp/StopTransfer',
        request_serializer=warp__pb2.StopInfo.SerializeToString,
        response_deserializer=warp__pb2.VoidType.FromString,
        )
    self.Ping = channel.unary_unary(
        '/Warp/Ping',
        request_serializer=warp__pb2.LookupName.SerializeToString,
        response_deserializer=warp__pb2.VoidType.FromString,
        )
    self.GetCertificate = channel.unary_unary(
        '/Warp/GetCertificate',
        request_serializer=warp__pb2.LookupName.SerializeToString,
        response_deserializer=warp__pb2.Certificate.FromString,
        )


class WarpServicer(object):
  """************ Important! ***************

  If you change anything here, you *must* run 'generate-protobuf' to update the
  generated stub files.

  Never change the existing members and member values of messages, only add new ones.

  """

  def CheckDuplexConnection(self, request, context):
    """Sender methods
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def WaitForDuplexConnection(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetRemoteMachineInfo(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetRemoteMachineAvatar(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def ProcessTransferOpRequest(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def PauseTransferOp(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def AcceptTransferOpRequest(self, request, context):
    """Receiver methods
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def StartTransfer(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def CancelTransferOpRequest(self, request, context):
    """Both
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def StopTransfer(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def Ping(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def GetCertificate(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_WarpServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'CheckDuplexConnection': grpc.unary_unary_rpc_method_handler(
          servicer.CheckDuplexConnection,
          request_deserializer=warp__pb2.LookupName.FromString,
          response_serializer=warp__pb2.HaveDuplex.SerializeToString,
      ),
      'WaitForDuplexConnection': grpc.unary_unary_rpc_method_handler(
          servicer.WaitForDuplexConnection,
          request_deserializer=warp__pb2.LookupName.FromString,
          response_serializer=warp__pb2.HaveDuplex.SerializeToString,
      ),
      'GetRemoteMachineInfo': grpc.unary_unary_rpc_method_handler(
          servicer.GetRemoteMachineInfo,
          request_deserializer=warp__pb2.LookupName.FromString,
          response_serializer=warp__pb2.RemoteMachineInfo.SerializeToString,
      ),
      'GetRemoteMachineAvatar': grpc.unary_stream_rpc_method_handler(
          servicer.GetRemoteMachineAvatar,
          request_deserializer=warp__pb2.LookupName.FromString,
          response_serializer=warp__pb2.RemoteMachineAvatar.SerializeToString,
      ),
      'ProcessTransferOpRequest': grpc.unary_unary_rpc_method_handler(
          servicer.ProcessTransferOpRequest,
          request_deserializer=warp__pb2.TransferOpRequest.FromString,
          response_serializer=warp__pb2.VoidType.SerializeToString,
      ),
      'PauseTransferOp': grpc.unary_unary_rpc_method_handler(
          servicer.PauseTransferOp,
          request_deserializer=warp__pb2.OpInfo.FromString,
          response_serializer=warp__pb2.VoidType.SerializeToString,
      ),
      'AcceptTransferOpRequest': grpc.unary_unary_rpc_method_handler(
          servicer.AcceptTransferOpRequest,
          request_deserializer=warp__pb2.OpInfo.FromString,
          response_serializer=warp__pb2.VoidType.SerializeToString,
      ),
      'StartTransfer': grpc.unary_stream_rpc_method_handler(
          servicer.StartTransfer,
          request_deserializer=warp__pb2.OpInfo.FromString,
          response_serializer=warp__pb2.FileChunk.SerializeToString,
      ),
      'CancelTransferOpRequest': grpc.unary_unary_rpc_method_handler(
          servicer.CancelTransferOpRequest,
          request_deserializer=warp__pb2.OpInfo.FromString,
          response_serializer=warp__pb2.VoidType.SerializeToString,
      ),
      'StopTransfer': grpc.unary_unary_rpc_method_handler(
          servicer.StopTransfer,
          request_deserializer=warp__pb2.StopInfo.FromString,
          response_serializer=warp__pb2.VoidType.SerializeToString,
      ),
      'Ping': grpc.unary_unary_rpc_method_handler(
          servicer.Ping,
          request_deserializer=warp__pb2.LookupName.FromString,
          response_serializer=warp__pb2.VoidType.SerializeToString,
      ),
      'GetCertificate': grpc.unary_unary_rpc_method_handler(
          servicer.GetCertificate,
          request_deserializer=warp__pb2.LookupName.FromString,
          response_serializer=warp__pb2.Certificate.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'Warp', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))
