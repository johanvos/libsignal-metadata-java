module org.whispersystems.metadata {
    requires com.google.protobuf;
    requires org.whispersystems.protocol;
    exports org.signal.libsignal.metadata;
    exports org.signal.libsignal.metadata.certificate;
}
