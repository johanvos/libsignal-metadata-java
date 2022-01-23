package org.signal.libsignal.metadata;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import org.signal.libsignal.metadata.certificate.CertificateValidator;
import org.signal.libsignal.metadata.certificate.InvalidCertificateException;
import org.signal.libsignal.metadata.certificate.SenderCertificate;
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessage;
import org.signal.libsignal.metadata.protocol.UnidentifiedSenderMessageContent;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMacException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;
import org.whispersystems.libsignal.protocol.SignalMessage;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.libsignal.util.ByteUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.whispersystems.curve25519.java.sc_reduce;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidRegistrationIdException;
import org.whispersystems.libsignal.groups.GroupCipher;

import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.state.IdentityKeyStore;
import org.whispersystems.libsignal.state.SessionRecord;

public class SealedSessionCipher {

    private static final String TAG = SealedSessionCipher.class.getSimpleName();

    static final int MESSAGE_KEY_LEN = 32;
    static final int AUTH_TAG_LEN = 16;
    static final int PUBLIC_KEY_LEN = 32;
    static final String LABEL_R = "Sealed Sender v2: r";
    static final String LABEL_K = "Sealed Sender v2: K";
    static final String LABEL_DH_S = "Sealed Sender v2: DH-sender";

    private final SignalProtocolStore signalProtocolStore;
    private final String localE164Address;
    private final String localUuidAddress;
    private final int localDeviceId;
    
    static final int SEALED_SENDER_V2_VERSION = 2;

    public SealedSessionCipher(SignalProtocolStore signalProtocolStore,
            UUID localUuid,
            String localE164Address,
            int localDeviceId) {
        this.signalProtocolStore = signalProtocolStore;
        this.localUuidAddress = localUuid != null ? localUuid.toString() : null;
        this.localE164Address = localE164Address;
        this.localDeviceId = localDeviceId;
    }

    public byte[] encrypt(SignalProtocolAddress destinationAddress, SenderCertificate senderCertificate, byte[] paddedPlaintext)
            throws InvalidKeyException, UntrustedIdentityException {
        CiphertextMessage message = new SessionCipher(signalProtocolStore, destinationAddress).encrypt(paddedPlaintext);
        IdentityKeyPair ourIdentity = signalProtocolStore.getIdentityKeyPair();
        ECPublicKey theirIdentity = signalProtocolStore.getIdentity(destinationAddress).getPublicKey();

        ECKeyPair ephemeral = Curve.generateKeyPair();
        byte[] ephemeralSalt = ByteUtil.combine("UnidentifiedDelivery".getBytes(), theirIdentity.serialize(), ephemeral.getPublicKey().serialize());
        EphemeralKeys ephemeralKeys = calculateEphemeralKeys(theirIdentity, ephemeral.getPrivateKey(), ephemeralSalt);
        byte[] staticKeyCiphertext = encrypt(ephemeralKeys.cipherKey, ephemeralKeys.macKey, ourIdentity.getPublicKey().getPublicKey().serialize());

        byte[] staticSalt = ByteUtil.combine(ephemeralKeys.chainKey, staticKeyCiphertext);
        StaticKeys staticKeys = calculateStaticKeys(theirIdentity, ourIdentity.getPrivateKey(), staticSalt);
        UnidentifiedSenderMessageContent content = new UnidentifiedSenderMessageContent(message.getType(), senderCertificate, message.serialize());
        byte[] messageBytes = encrypt(staticKeys.cipherKey, staticKeys.macKey, content.getSerialized());

        return new UnidentifiedSenderMessage(ephemeral.getPublicKey(), staticKeyCiphertext, messageBytes).getSerialized();
    }

    public byte[] encrypt(SignalProtocolAddress destinationAddress, UnidentifiedSenderMessageContent content)
            throws InvalidKeyException, UntrustedIdentityException {
        System.err.println("SSC, encrypt usmc for type = "+content.getType());
        IdentityKeyPair ourIdentity = signalProtocolStore.getIdentityKeyPair();
        ECPublicKey theirIdentity = signalProtocolStore.getIdentity(destinationAddress).getPublicKey();
        System.err.println("SSC, ourIdentity = "+ ourIdentity);
        ECKeyPair ephemeral = Curve.generateKeyPair();
        byte[] ephemeralSalt = ByteUtil.combine("UnidentifiedDelivery".getBytes(), theirIdentity.serialize(), ephemeral.getPublicKey().serialize());
        EphemeralKeys ephemeralKeys = calculateEphemeralKeys(theirIdentity, ephemeral.getPrivateKey(), ephemeralSalt);
        byte[] staticKeyCiphertext = encrypt(ephemeralKeys.cipherKey, ephemeralKeys.macKey, ourIdentity.getPublicKey().getPublicKey().serialize());

        byte[] staticSalt = ByteUtil.combine(ephemeralKeys.chainKey, staticKeyCiphertext);
        StaticKeys staticKeys = calculateStaticKeys(theirIdentity, ourIdentity.getPrivateKey(), staticSalt);
        byte[] messageBytes = encrypt(staticKeys.cipherKey, staticKeys.macKey, content.getSerialized());

        byte[] messageData = new byte[messageBytes.length];
//        UnidentifiedSenderMessage pb = new UnidentifiedSenderMessage(theirIdentity, staticKeyCiphertext, messageBytes);
 UnidentifiedSenderMessage pb = new UnidentifiedSenderMessage(ephemeral.getPublicKey(), staticKeyCiphertext, messageBytes);

        byte[] serialized = pb.getSerialized();
        System.err.println("SSC, encrypted has " + serialized.length + " bytes and = " + Arrays.toString(serialized));
        return serialized;

    }

    public DecryptionResult decrypt(CertificateValidator validator, byte[] ciphertext, long timestamp)
            throws
            InvalidMetadataMessageException, InvalidMetadataVersionException,
            ProtocolInvalidMessageException, ProtocolInvalidKeyException,
            ProtocolNoSessionException, ProtocolLegacyMessageException,
            ProtocolInvalidVersionException, ProtocolDuplicateMessageException,
            ProtocolInvalidKeyIdException, ProtocolUntrustedIdentityException,
            SelfSendException {
        System.err.println("SealedSessionCipher, decrypt, length = " + ciphertext.length);// + " and content = " + Arrays.toString(ciphertext));
        UnidentifiedSenderMessageContent content;
        int version = ByteUtil.highBitsToInt(ciphertext[0]);
        System.err.println("[SEALEDSESSIONCIPHER] Need to decrypt "+Arrays.toString(ciphertext));
        IdentityKeyPair ourIdentity = signalProtocolStore.getIdentityKeyPair();

        try {
            if (version == 1) {
                UnidentifiedSenderMessage wrapper = new UnidentifiedSenderMessage(ciphertext);
                byte[] ephemeralSalt = ByteUtil.combine("UnidentifiedDelivery".getBytes(), ourIdentity.getPublicKey().getPublicKey().serialize(), wrapper.getEphemeral().serialize());
                System.err.println("[SSC] decrypt, esalt = "+Arrays.toString(ephemeralSalt));
                EphemeralKeys ephemeralKeys = calculateEphemeralKeys(wrapper.getEphemeral(), ourIdentity.getPrivateKey(), ephemeralSalt);
                byte[] staticKeyBytes = decrypt(ephemeralKeys.cipherKey, ephemeralKeys.macKey, wrapper.getEncryptedStatic());
                System.err.println("[SSC] staticKeybytes = " + Arrays.toString(staticKeyBytes));
                ECPublicKey staticKey = Curve.decodePoint(staticKeyBytes, 0);
                byte[] staticSalt = ByteUtil.combine(ephemeralKeys.chainKey, wrapper.getEncryptedStatic());
                System.err.println("[SSC] staticSalt = "+ Arrays.toString(staticSalt));
                StaticKeys staticKeys = calculateStaticKeys(staticKey, ourIdentity.getPrivateKey(), staticSalt);
                byte[] messageBytes = decrypt(staticKeys.cipherKey, staticKeys.macKey, wrapper.getEncryptedMessage());
                System.err.println("[SSC] mB = "+Arrays.toString(messageBytes));
                content = new UnidentifiedSenderMessageContent(messageBytes);

                validator.validate(content.getSenderCertificate(), timestamp);
                if (!MessageDigest.isEqual(content.getSenderCertificate().getKey().serialize(), staticKeyBytes)) {
                    throw new InvalidKeyException("Sender's certificate key does not match key used in message");
                }

            } else if (version == 2) {
                int idx = 1;
                int msgSize = ciphertext.length - MESSAGE_KEY_LEN - AUTH_TAG_LEN - PUBLIC_KEY_LEN - 1;
                ourIdentity.getPrivateKey().serialize();
                byte[] encrypted_message_key = new byte[MESSAGE_KEY_LEN];
                byte[] encrypted_authentication_tag = new byte[AUTH_TAG_LEN];
                byte[] theirPublicKey = new byte[1 + PUBLIC_KEY_LEN];
                theirPublicKey[0] = 0x5;
                byte[] encrypted_message = new byte[msgSize];
                System.arraycopy(ciphertext, idx, encrypted_message_key, 0, MESSAGE_KEY_LEN);
                idx = idx + MESSAGE_KEY_LEN;
                System.arraycopy(ciphertext, idx, encrypted_authentication_tag, 0, AUTH_TAG_LEN);
                idx = idx + AUTH_TAG_LEN;
                System.arraycopy(ciphertext, idx, theirPublicKey, 1, PUBLIC_KEY_LEN);
                idx = idx + PUBLIC_KEY_LEN;
                System.arraycopy(ciphertext, idx, encrypted_message, 0, msgSize);
                System.err.println("MSGKEY = "+Arrays.toString(encrypted_message_key));
                System.err.println("AUTH_TAG = "+Arrays.toString(encrypted_authentication_tag));
                System.err.println("PUBKEY = "+Arrays.toString(theirPublicKey));
                System.err.println("first byte encryptedMessage = " + encrypted_message[0] + " at position " + idx);

                IdentityKeyPair ik = signalProtocolStore.getIdentityKeyPair();

                ECPublicKey theirPubKey = Curve.decodePoint(theirPublicKey, 0);
                byte[] answer = apply_agreement_xor(ik, theirPubKey, false, encrypted_message_key);
                DerivedKeys keys = calculateDerivedKeys(answer);
                ECPublicKey calced = Curve.createPublicKeyFromPrivateKey(keys.e.serialize());
                byte[] nonce = new byte[12];
                try {
                    Cipher cipher = Cipher.getInstance("AES/GCM-SIV/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keys.k, "AES"), new IvParameterSpec(nonce));
                    byte[] messageBytes = cipher.doFinal(encrypted_message);
                    System.err.println("First byte messageBytes = " + Arrays.toString(messageBytes));

                    content = new UnidentifiedSenderMessageContent(messageBytes);
                    System.err.println("got content: "+Arrays.toString(content.getContent()));
                    int ch = content.getContentHint();
                    byte[] gid = content.getGroupId().get();
                    System.err.println("hint = "+ch+" and gid = "+Arrays.toString(gid));
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new IllegalArgumentException("bummer: " + e);
                }
            } else {
                throw new IllegalArgumentException("Can not process UnidentifiedSenderMessage with type " + version);
            }
            boolean isLocalE164 = localE164Address != null && localE164Address.equals(content.getSenderCertificate().getSenderE164().orElse(null));
            boolean isLocalUuid = localUuidAddress != null && localUuidAddress.equals(content.getSenderCertificate().getSenderUuid().orElse(null));

            if ((isLocalE164 || isLocalUuid) && content.getSenderCertificate().getSenderDeviceId() == localDeviceId) {
                throw new SelfSendException();
            }
        } catch (Exception e) {
//        } catch (InvalidKeyException | InvalidMacException | InvalidCertificateException e) {
            throw new InvalidMetadataMessageException(e);
        }

        try {
            return new DecryptionResult(content.getSenderCertificate().getSenderUuid(),
                    content.getSenderCertificate().getSenderE164(),
                    content.getSenderCertificate().getSenderDeviceId(),
                    content.getGroupId(),
                    decrypt(content));
        } catch (InvalidMessageException e) {
            throw new ProtocolInvalidMessageException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId());
        } catch (InvalidKeyException e) {
            throw new ProtocolInvalidKeyException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId());
        } catch (NoSessionException e) {
            e.printStackTrace();
            throw new ProtocolNoSessionException(e, content);
        } catch (LegacyMessageException e) {
            throw new ProtocolLegacyMessageException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId());
        } catch (InvalidVersionException e) {
            throw new ProtocolInvalidVersionException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId());
        } catch (DuplicateMessageException e) {
            throw new ProtocolDuplicateMessageException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId());
        } catch (InvalidKeyIdException e) {
            throw new ProtocolInvalidKeyIdException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId());
        } catch (UntrustedIdentityException e) {
            throw new ProtocolUntrustedIdentityException(e, content.getSenderCertificate().getSender(), content.getSenderCertificate().getSenderDeviceId());
        }
    }

    public byte[] multiRecipientEncrypt(List<SignalProtocolAddress> destinations, UnidentifiedSenderMessageContent usmc)
            throws
            InvalidKeyException, NoSessionException,
            UntrustedIdentityException, InvalidRegistrationIdException
    {
     //   System.err.println("MRE, umc = "+ Arrays.toString(usmc.getSerialized()));
        System.err.println("MRE, type = " + usmc.getType());
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte versionByte = (byte) (SEALED_SENDER_V2_VERSION | SEALED_SENDER_V2_VERSION <<4);
            baos.write(versionByte);
            
            int count = destinations.size();
            byte[] vi = varint(count);
            baos.write(vi);
            List<SessionRecord> destinationSessions
                    = this.signalProtocolStore.loadExistingSessions(destinations);
            byte[] m = new byte[MESSAGE_KEY_LEN];
            try {
                SecureRandom.getInstanceStrong().nextBytes(m);
            } catch (NoSuchAlgorithmException ex) {
                ex.printStackTrace();
            }
            DerivedKeys keys = calculateDerivedKeys(m);
            ECPublicKey ePub = Curve.createPublicKeyFromPrivateKey(keys.e.serialize());
            IdentityKeyPair ourKeys = new IdentityKeyPair(new IdentityKey(ePub),keys.e);
            byte[] nonce = new byte[12];

            Cipher cipher = Cipher.getInstance("AES/GCM-SIV/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keys.k, "AES"), new IvParameterSpec(nonce));
            byte[] ciphertext = cipher.doFinal(usmc.getSerialized());
            System.err.println("ENCRYPT, ciphertext length = "+ciphertext.length);
        //    System.err.println("ct = "+Arrays.toString(ciphertext));
            
            for (int i = 0; i < count; i++) {
                SignalProtocolAddress destination = destinations.get(i);
                SessionRecord session = destinationSessions.get(i);
                UUID theirUuid = UUID.fromString(destination.getName());
                IdentityKey theirIdentity = signalProtocolStore.getIdentity(destination);
                int theirRegistrationId = session.getRemoteRegistrationId();
                System.err.println("REGID = "+theirRegistrationId);
                if (theirRegistrationId > ((1 <<14) -1)) {
                    throw new InvalidRegistrationIdException(destination, "remote registration id "+theirRegistrationId+" does not fit in 14 bits");
                }
                baos.writeBytes(uuidToBytes(theirUuid));
                baos.write(varint(destination.getDeviceId()));
                byte reghigh = (byte)(theirRegistrationId/256);
                byte reglow = (byte)(theirRegistrationId%256);
                baos.write(reghigh);
                baos.write(reglow);
                byte[] c_i = apply_agreement_xor(ourKeys, theirIdentity.getPublicKey(), true, m);
                baos.writeBytes(c_i);
                byte[] at_i = computeAuthenticationTag(ourKeys, theirIdentity, true, ePub, c_i);
                baos.writeBytes(at_i);
            }
        //    System.err.println("multi-encrypt, pkb = "+Arrays.toString(ePub.getPublicKeyBytes()));
            baos.writeBytes(ePub.getPublicKeyBytes());
            baos.writeBytes(ciphertext);
            byte[] serialized = baos.toByteArray();
     //       System.err.println("result of multi-enc = "+Arrays.toString(serialized));
            return serialized;
//
//    // Unsafely access the native handles for the recipients and sessions,
//    // because try-with-resources syntax doesn't support a List of resources.
//    long[] recipientHandles = new long[recipients.size()];
//    int i = 0;
//    for (SignalProtocolAddress nextRecipient : recipients) {
//      recipientHandles[i] = nextRecipient.unsafeNativeHandleWithoutGuard();
//      i++;
//    }   
//
//    long[] recipientSessionHandles = new long[recipientSessions.size()];
//    i = 0;
//    for (SessionRecord nextSession : recipientSessions) {
//      recipientSessionHandles[i] = nextSession.unsafeNativeHandleWithoutGuard();
//      i++;
//    }   
//
//    try (NativeHandleGuard contentGuard = new NativeHandleGuard(content)) {
//      byte[] result = Native.SealedSessionCipher_MultiRecipientEncrypt(
//        recipientHandles,
//        recipientSessionHandles,
//        contentGuard.nativeHandle(),
//        this.signalProtocolStore,
//        null);
//      // Manually keep the lists of recipients and sessions from being garbage collected
//      // while we're using their native handles.
//      Native.keepAlive(recipients);
//      Native.keepAlive(recipientSessions);
//      return result;
//    }   
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        } catch (NoSuchPaddingException ex) {
            ex.printStackTrace();
        } catch (InvalidAlgorithmParameterException ex) {
            ex.printStackTrace();
        } catch (IllegalBlockSizeException ex) {
            ex.printStackTrace();
        } catch (BadPaddingException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        } catch (java.security.InvalidKeyException ex) {
            ex.printStackTrace();
        }
        return null;
    }

    static byte[] multiRecipientMessageForSingleRecipient(byte[] data) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int version = data[0];
        if (version >> 4 != SEALED_SENDER_V2_VERSION) {
            throw new IllegalArgumentException("Invalid version "+version+" for multiRecipientMessages");
        }
        int cnt = (int)data[1];
        if (cnt > 127) throw new IllegalArgumentException ("group limited to 127 currently");
        int idx = 2;
        int LEN = MESSAGE_KEY_LEN+AUTH_TAG_LEN;
        List<byte[]> messages = new ArrayList<>(cnt);
        System.err.println("MRMFSR, cnt = "+cnt);
        for (int i = 0; i < cnt; i++) {
            byte[] msg = new byte[LEN];
            idx = idx + 16; // uuid
            idx = idx + 1; // device_id
            idx = idx + 2; // registration_id
            System.arraycopy(data, idx, msg, 0, LEN);
            messages.add(msg);
            System.err.println("MSGKEY + LEN = "+Arrays.toString(msg));
            idx = idx + LEN;
        }
        int remaining = data.length - idx;
        int remstart = idx;
        System.err.println("dataremaining = "+data[remaining]+" and then "+ data[remaining+1]+" and idx = " + idx+" and rem = "+remaining);
        byte[] serialized = new byte[cnt*(1+LEN+remaining)];
        idx = 0;
        for (int i = 0; i < cnt; i++) {
            serialized[idx] = data[0];
            idx = idx + 1;
            System.arraycopy(messages.get(i), 0, serialized, idx, LEN);
            idx = idx + LEN;
            System.arraycopy(data, remstart, serialized, idx, remaining);
        }
        System.err.println("SingleRec has "+serialized.length+" bytes");
        return serialized;
    }

    public int getSessionVersion(SignalProtocolAddress remoteAddress) {
        return new SessionCipher(signalProtocolStore, remoteAddress).getSessionVersion();
    }

    public int getRemoteRegistrationId(SignalProtocolAddress remoteAddress) {
        return new SessionCipher(signalProtocolStore, remoteAddress).getRemoteRegistrationId();
    }

    private EphemeralKeys calculateEphemeralKeys(ECPublicKey ephemeralPublic, ECPrivateKey ephemeralPrivate, byte[] salt) throws InvalidKeyException {
        try {
            byte[] ephemeralSecret = Curve.calculateAgreement(ephemeralPublic, ephemeralPrivate);
            byte[] ephemeralDerived = new HKDFv3().deriveSecrets(ephemeralSecret, salt, new byte[0], 96);
            byte[][] ephemeralDerivedParts = ByteUtil.split(ephemeralDerived, 32, 32, 32);

            return new EphemeralKeys(ephemeralDerivedParts[0], ephemeralDerivedParts[1], ephemeralDerivedParts[2]);
        } catch (ParseException e) {
            throw new AssertionError(e);
        }
    }

    private StaticKeys calculateStaticKeys(ECPublicKey staticPublic, ECPrivateKey staticPrivate, byte[] salt) throws InvalidKeyException {
        try {
            byte[] staticSecret = Curve.calculateAgreement(staticPublic, staticPrivate);
            byte[] staticDerived = new HKDFv3().deriveSecrets(staticSecret, salt, new byte[0], 96);
            byte[][] staticDerivedParts = ByteUtil.split(staticDerived, 32, 32, 32);

            return new StaticKeys(staticDerivedParts[1], staticDerivedParts[2]);
        } catch (ParseException e) {
            throw new AssertionError(e);
        }
    }

    private byte[] decrypt(UnidentifiedSenderMessageContent message)
            throws InvalidVersionException, InvalidMessageException, InvalidKeyException, DuplicateMessageException, InvalidKeyIdException, UntrustedIdentityException, LegacyMessageException, NoSessionException {
        SignalProtocolAddress sender = getPreferredAddress(signalProtocolStore, message.getSenderCertificate());
        System.err.println("SSC, decrypt USMC, type = " + message.getType());
        switch (message.getType()) {
            case CiphertextMessage.WHISPER_TYPE:
                return new SessionCipher(signalProtocolStore, sender).decrypt(new SignalMessage(message.getContent()));
            case CiphertextMessage.PREKEY_TYPE:
                return new SessionCipher(signalProtocolStore, sender).decrypt(new PreKeySignalMessage(message.getContent()));
            case CiphertextMessage.SENDERKEY_TYPE:
                return new GroupCipher(signalProtocolStore, sender).decrypt(message.getContent());
            default:
                throw new InvalidMessageException("Unknown type: " + message.getType());
        }
    }

    private byte[] encrypt(SecretKeySpec cipherKey, SecretKeySpec macKey, byte[] plaintext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, cipherKey, new IvParameterSpec(new byte[16]));

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(macKey);

            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] ourFullMac = mac.doFinal(ciphertext);
            byte[] ourMac = ByteUtil.trim(ourFullMac, 10);

            return ByteUtil.combine(ciphertext, ourMac);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new AssertionError(e);
        }
    }

    private byte[] decrypt(SecretKeySpec cipherKey, SecretKeySpec macKey, byte[] ciphertext) throws InvalidMacException {
        try {
            if (ciphertext.length < 10) {
                throw new InvalidMacException("Ciphertext not long enough for MAC!");
            }

            byte[][] ciphertextParts = ByteUtil.split(ciphertext, ciphertext.length - 10, 10);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(macKey);

            byte[] digest = mac.doFinal(ciphertextParts[0]);
            byte[] ourMac = ByteUtil.trim(digest, 10);
            byte[] theirMac = ciphertextParts[1];
            System.err.println("[SSC] ourMac = "+ Arrays.toString(ourMac));
            System.err.println("[SSC] theirMac = " + Arrays.toString(theirMac));
            if (!MessageDigest.isEqual(ourMac, theirMac)) {
                throw new InvalidMacException("Bad mac!");
            }

            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, cipherKey, new IvParameterSpec(new byte[16]));

            return cipher.doFinal(ciphertextParts[0]);
        } catch (NoSuchAlgorithmException | java.security.InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new AssertionError(e);
        }
    }

    private static SignalProtocolAddress getPreferredAddress(SignalProtocolStore store, SenderCertificate certificate) {
        SignalProtocolAddress uuidAddress = certificate.getSenderUuid().isPresent() ? new SignalProtocolAddress(certificate.getSenderUuid().get(), certificate.getSenderDeviceId()) : null;
        SignalProtocolAddress e164Address = certificate.getSenderE164().isPresent() ? new SignalProtocolAddress(certificate.getSenderE164().get(), certificate.getSenderDeviceId()) : null;
        System.err.println("GPA, uuida = "+uuidAddress);
        System.err.println("GPA, e164 = "+e164Address);
        if (uuidAddress != null && store.containsSession(uuidAddress)) {
            return uuidAddress;
        } else if (e164Address != null && store.containsSession(e164Address)) {
            return e164Address;
        } else {
            if (uuidAddress != null) {
                return uuidAddress;
            }
            return new SignalProtocolAddress(certificate.getSender(), certificate.getSenderDeviceId());
        }
    }

    public static class DecryptionResult {

        private final Optional<String> senderUuid;
        private final Optional<String> senderE164;
        private final int deviceId;
        private final Optional<byte[]> groupId;
        private final byte[] paddedMessage;

        private DecryptionResult(Optional<String> senderUuid, Optional<String> senderE164,
                int deviceId, Optional<byte[]> groupId, byte[] paddedMessage) {
            this.senderUuid = senderUuid;
            this.senderE164 = senderE164;
            this.deviceId = deviceId;
            this.groupId = groupId;
            this.paddedMessage = paddedMessage;
        }

        public Optional<String> getSenderUuid() {
            return senderUuid;
        }

        public Optional<String> getSenderE164() {
            return senderE164;
        }

        public int getDeviceId() {
            return deviceId;
        }

        public byte[] getPaddedMessage() {
            return paddedMessage;
        }

        public Optional<byte[]> getGroupId() {
            return groupId;
        }

    }

    private static class EphemeralKeys {

        private final byte[] chainKey;
        private final SecretKeySpec cipherKey;
        private final SecretKeySpec macKey;

        private EphemeralKeys(byte[] chainKey, byte[] cipherKey, byte[] macKey) {
            this.chainKey = chainKey;
            this.cipherKey = new SecretKeySpec(cipherKey, "AES");
            this.macKey = new SecretKeySpec(macKey, "HmacSHA256");
        }
    }

    private static class StaticKeys {

        private final SecretKeySpec cipherKey;
        private final SecretKeySpec macKey;

        private StaticKeys(byte[] cipherKey, byte[] macKey) {
            this.cipherKey = new SecretKeySpec(cipherKey, "AES");
            this.macKey = new SecretKeySpec(macKey, "HmacSHA256");
        }
    }

    UnidentifiedSenderMessageContent getNewUsmContent(byte[] ctext, IdentityKeyStore identityStore) throws InvalidMetadataMessageException, InvalidCertificateException {
        return new UnidentifiedSenderMessageContent(SealedSessionCipher_DecryptToUsmc(ctext, identityStore));
    }

    byte[] SealedSessionCipher_DecryptToUsmc(byte[] ctext, IdentityKeyStore identityStore) {
        return sealed_sender_decrypt_to_usmc(ctext, identityStore);
    }

    private byte[] sealed_sender_decrypt_to_usmc(byte[] ctext, IdentityKeyStore identityStore) {
        deserialize(ctext);
        return null;
    }

    private void deserialize(byte[] ctext) {

    }

    static byte[] apply_agreement_xor(IdentityKeyPair ourKeyPair, ECPublicKey theirPublicKey,
            boolean direction, byte[] input) throws InvalidKeyException {
        byte[] agreementKeyInput = createAgreementKeyInput(ourKeyPair, theirPublicKey, direction, input);
        HKDF hkdf = HKDFv3.createFor(3);
        byte[] secrets = hkdf.deriveSecrets(agreementKeyInput, "Sealed Sender v2: DH".getBytes(), MESSAGE_KEY_LEN);
        for (int i = 0; i < input.length; i++) {
            secrets[i] = (byte) (secrets[i] ^ input[i]);
        }
        return secrets;
    }

    static byte[] createAgreementKeyInput(IdentityKeyPair ourKeyPair, ECPublicKey theirPublicKey,
            boolean direction, byte[] input) throws InvalidKeyException {
        byte[] answer = new byte[0];
        byte[] agreement = Curve.calculateAgreement(theirPublicKey, ourKeyPair.getPrivateKey());
        byte[] theirpubkey = theirPublicKey.serialize();
        byte[] ourpubkey = ourKeyPair.getPublicKey().serialize();
        int alen = agreement.length + theirpubkey.length + ourpubkey.length;
        int theirPubKeyLen = theirpubkey.length;
        int ourPubKeyLen = ourpubkey.length;
        int agreementLen = agreement.length;
        byte[] agreementKeyInput = new byte[alen];
        System.arraycopy(agreement, 0, agreementKeyInput, 0, agreementLen);
        if (direction) {
            System.arraycopy(ourpubkey, 0, agreementKeyInput, agreementLen, ourPubKeyLen);
            System.arraycopy(theirpubkey, 0, agreementKeyInput, agreementLen + ourPubKeyLen, theirPubKeyLen);
        } else {
            System.arraycopy(theirpubkey, 0, agreementKeyInput, agreementLen, theirPubKeyLen);
            System.arraycopy(ourpubkey, 0, agreementKeyInput, agreementLen + theirPubKeyLen, ourPubKeyLen);
        }
        return agreementKeyInput;
    }

    static byte[] reduce(byte[] s) {
        if (s.length != 64) {
            throw new IllegalArgumentException("Length of input should be 64 bytes but was " + s.length);
        }
        byte[] copy = new byte[s.length];
        System.arraycopy(s, 0, copy, 0, s.length);
        sc_reduce.sc_reduce(copy);
        byte[] answer = new byte[32];
        System.arraycopy(copy, 0, answer, 0, 32);
        return answer;
    }

    static DerivedKeys calculateDerivedKeys(byte[] m) {
        HKDF kdf = HKDF.createFor(3);
        byte[] r = kdf.deriveSecrets(m, LABEL_R.getBytes(), 64);
        byte[] k = kdf.deriveSecrets(m, LABEL_K.getBytes(), 32);
        byte[] reduced = reduce(r);
        reduced[0] &= 0xF8;
        reduced[31] &= 0x7F;
        reduced[31] |= 0x40;
        DerivedKeys answer = new DerivedKeys(Curve.decodePrivatePoint(reduced), k);
        return answer;
    }
    
    static byte[] computeAuthenticationTag(IdentityKeyPair ourKeys, IdentityKey theirKey, boolean direction,
            ECPublicKey ephemeralPubKey, byte[] encryptedMessageKey) throws InvalidKeyException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] agreement = Curve.calculateAgreement(theirKey.getPublicKey(), ourKeys.getPrivateKey());
            baos.write(agreement);
            baos.write(ephemeralPubKey.serialize());
            baos.write(encryptedMessageKey);
            if (direction) {
                baos.write(ourKeys.getPublicKey().serialize());
                baos.write(theirKey.getPublicKey().serialize());
            } else {
                baos.write(theirKey.getPublicKey().serialize());
                baos.write(ourKeys.getPublicKey().serialize());
            } HKDF hkdf = HKDFv3.createFor(3);
        byte[] secrets = hkdf.deriveSecrets(baos.toByteArray(), LABEL_DH_S.getBytes(), AUTH_TAG_LEN);
return secrets;
        } catch (IOException ex) {
            ex.printStackTrace();
        }
      return null;
    }
    
  static byte[] uuidToBytes(UUID uuid) {
    ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
    bb.putLong(uuid.getMostSignificantBits());
    bb.putLong(uuid.getLeastSignificantBits());
    return bb.array();
  }
  
  static byte[] varint(int src) {
      int len = 1;
      int tmp = src;
      while (tmp > 127) {
          tmp >>>= 7;
          len++;
      }
      byte[] answer = new byte[len];
      tmp = src;
      int i = 0;
      while (i < len -1) {
          answer[i] = (byte)((tmp & 127) | 128);
          tmp >>>= 7;
          i++;
      }
      answer[i] = (byte)tmp;
      return answer;
  }
  
    static class DerivedKeys {

        ECPrivateKey e;
        byte[] k;

        DerivedKeys(ECPrivateKey key, byte[] box) {
            this.e = key;
            this.k = box;
        }
    }

    enum Direction {
        Sending,
        Receiving
    }
}
