package org.signal.libsignal.metadata.protocol;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.util.Optional;
import java.util.logging.Logger;

import org.signal.libsignal.metadata.InvalidMetadataMessageException;
import org.signal.libsignal.metadata.SignalProtos;
import org.signal.libsignal.metadata.SignalProtos.UnidentifiedSenderMessage.Message.ContentHint;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.protocol.CiphertextMessage;

public class UnidentifiedSenderMessageContent {

    public static final int CONTENT_HINT_DEFAULT = 0;
    public static final int CONTENT_HINT_RESENDABLE = 1;
    public static final int CONTENT_HINT_IMPLICIT = 2;

    private int type;
    private final SenderCertificate senderCertificate;
    private final byte[] content;
    private final byte[] serialized;
    private final Optional<byte[]> groupId;
    private int contentHint;

    private static final Logger LOG = Logger.getLogger(UnidentifiedSenderMessageContent.class.getName());

    public UnidentifiedSenderMessageContent(byte[] serialized) throws InvalidMetadataMessageException, InvalidCertificateException {
        try {
            SignalProtos.UnidentifiedSenderMessage.Message message = SignalProtos.UnidentifiedSenderMessage.Message.parseFrom(serialized);
            LOG.info("construct usmc with type = " + message.getType());
            if (!message.hasType() || !message.hasSenderCertificate() || !message.hasContent()) {
                throw new InvalidMetadataMessageException("Missing fields");
            }
            LOG.fine("GROUPID = " + message.getGroupId());
            this.groupId = Optional.of(message.getGroupId().toByteArray());
            switch (message.getType()) {
                case MESSAGE:
                    this.type = CiphertextMessage.WHISPER_TYPE;
                    break;
                case PREKEY_MESSAGE:
                    this.type = CiphertextMessage.PREKEY_TYPE;
                    break;
                case SENDERKEY_MESSAGE:
                    this.type = CiphertextMessage.SENDERKEY_TYPE;
                    break;
                case PLAINTEXT_CONTENT:
                    this.type = CiphertextMessage.PLAINTEXT_CONTENT_TYPE;
                    break;
                default:
                    throw new InvalidMetadataMessageException("Unknown type: " + message.getType().getNumber());
            }

            this.senderCertificate = new SenderCertificate(message.getSenderCertificate().toByteArray());
            this.content = message.getContent().toByteArray();
            this.serialized = serialized;
            this.contentHint = message.getContentHint().getNumber();
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidMetadataMessageException(e);
        }
    }

    public UnidentifiedSenderMessageContent(CiphertextMessage message,
            SenderCertificate senderCertificate,
            int contentHint,
            Optional<byte[]> groupId) {
        try {
            LOG.fine("messagetype = " + message.getType() + " and prototype  = " + getProtoType(message.getType()));
            int protoType = getProtoType(message.getType());
            SignalProtos.UnidentifiedSenderMessage.Message.Builder builder = SignalProtos.UnidentifiedSenderMessage.Message.newBuilder()
                    .setSenderCertificate(SignalProtos.SenderCertificate.parseFrom(senderCertificate.getSerialized()))
                    .setContent(ByteString.copyFrom(message.serialize()))
                    .setType(SignalProtos.UnidentifiedSenderMessage.Message.Type.forNumber(protoType));
            if (groupId.isPresent()) {
                builder.setGroupId(ByteString.copyFrom(groupId.get()));
            }
            if (contentHint > 0) {
                builder.setContentHint(ContentHint.forNumber(contentHint));

            }
            this.serialized = builder.build().toByteArray();

        } catch (InvalidProtocolBufferException ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }
        this.type = message.getType();
        this.senderCertificate = senderCertificate;
        this.content = message.serialize();
        this.groupId = groupId;
        this.contentHint = contentHint;
    }

    public UnidentifiedSenderMessageContent(int type, SenderCertificate senderCertificate, byte[] content) {
        try {

            this.serialized = SignalProtos.UnidentifiedSenderMessage.Message.newBuilder()
                    .setType(SignalProtos.UnidentifiedSenderMessage.Message.Type.valueOf(getProtoType(type)))
                    .setSenderCertificate(SignalProtos.SenderCertificate.parseFrom(senderCertificate.getSerialized()))
                    .setContent(ByteString.copyFrom(content))
                    .build()
                    .toByteArray();

            this.type = type;
            this.senderCertificate = senderCertificate;
            this.content = content;
            this.groupId = Optional.empty();
        } catch (InvalidProtocolBufferException e) {
            throw new AssertionError(e);
        }
    }

    public int getType() {
        return type;
    }

    public SenderCertificate getSenderCertificate() {
        return senderCertificate;
    }

    public byte[] getContent() {
        return content;
    }

    public byte[] getSerialized() {
        return serialized;
    }

    public Optional<byte[]> getGroupId() {
        return groupId;
    }

    private int getProtoType(int type) {
        switch (type) {
            case CiphertextMessage.WHISPER_TYPE:
                return SignalProtos.UnidentifiedSenderMessage.Message.Type.MESSAGE_VALUE;
            case CiphertextMessage.PREKEY_TYPE:
                return SignalProtos.UnidentifiedSenderMessage.Message.Type.PREKEY_MESSAGE_VALUE;
            case CiphertextMessage.SENDERKEY_TYPE:
                return SignalProtos.UnidentifiedSenderMessage.Message.Type.SENDERKEY_MESSAGE_VALUE;
            case CiphertextMessage.PLAINTEXT_CONTENT_TYPE:
                return SignalProtos.UnidentifiedSenderMessage.Message.Type.PLAINTEXT_CONTENT_VALUE;

            default:
                throw new AssertionError(type);
        }
    }

    public int getContentHint() {
        return this.contentHint;
    }

}
