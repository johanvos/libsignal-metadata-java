module org.whispersystems.metadata {
    requires com.google.protobuf;
    requires org.whispersystems.protocol;
    requires org.whispersystems.curve25519;
    exports org.signal.libsignal.metadata;
    exports org.signal.libsignal.metadata.certificate;
    exports org.signal.libsignal.metadata.protocol;
}
