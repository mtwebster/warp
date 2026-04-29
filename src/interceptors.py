#!/usr/bin/python3

import zlib
import grpc
import grpc.aio
import logging

import prefs


class _StreamResponseWrapper:
    def __init__(self, call):
        self._call = call

    def __aiter__(self):
        return self

    async def __anext__(self):
        chunk = await self._call.__anext__()

        try:
            if not chunk.chunk:
                return chunk
            chunk.chunk = zlib.decompress(chunk.chunk)
            return chunk
        except StopAsyncIteration:
            raise
        except Exception as e:
            logging.warning("Decompression error: %s" % e)
            raise

    def cancel(self):
        return self._call.cancel()

    def __getattr__(self, name):
        return getattr(self._call, name)


class ChunkDecompressor(grpc.aio.UnaryStreamClientInterceptor):
    async def intercept_unary_stream(self, continuation, client_call_details, request):
        if client_call_details.method != "/Warp/StartTransfer":
            return await continuation(client_call_details, request)

        try:
            use_comp = request.use_compression
        except AttributeError:
            use_comp = False

        logging.debug("Transfer using compression: %d" % use_comp)

        call = await continuation(client_call_details, request)

        if not use_comp:
            return call

        return _StreamResponseWrapper(call)


def _wrap_unary_stream_handler(handler, fn):
    return grpc.unary_stream_rpc_method_handler(
        fn(handler.unary_stream),
        request_deserializer=handler.request_deserializer,
        response_serializer=handler.response_serializer,
    )


class ChunkCompressor(grpc.aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        if handler_call_details.method != "/Warp/StartTransfer":
            return await continuation(handler_call_details)

        handler = await continuation(handler_call_details)
        if handler is None:
            return None

        # /Warp/StartTransfer is unary-stream; if anything else slips through, pass through.
        if handler.request_streaming or not handler.response_streaming:
            return handler

        def compression_wrapper(behavior):
            async def replacement_behavior(request, servicer_context):
                # The sender's compression preference is on OpInfo.use_compression.
                try:
                    use_comp = request.use_compression
                except AttributeError:
                    use_comp = False

                logging.debug("Transfer using compression: %d" % use_comp)

                if not use_comp:
                    async for chunk in behavior(request, servicer_context):
                        yield chunk
                    return

                comp_level = prefs.get_compression_level()

                try:
                    async for chunk in behavior(request, servicer_context):
                        if not chunk.chunk:
                            # Directory or symlink, or file terminator block.
                            yield chunk
                        else:
                            chunk.chunk = zlib.compress(chunk.chunk, level=comp_level)
                            yield chunk
                except Exception as e:
                    logging.warning("Compression error: %s" % e)
                    await servicer_context.abort(
                        code=grpc.StatusCode.DATA_LOSS,
                        details='Something went wrong with data compression: %s' % e,
                    )

            return replacement_behavior

        return _wrap_unary_stream_handler(handler, compression_wrapper)
