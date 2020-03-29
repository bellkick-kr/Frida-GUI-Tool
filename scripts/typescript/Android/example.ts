const pointerSize = Process.pointerSize;
const SV_OFFSET_FLAGS = pointerSize + 4;
const PVGV_OFFSET_NAMEHEK = 4 * pointerSize;

const SVt_PVGV = 9;

Interceptor.attach(Module.getExportByName(null, 'Perl_pp_entersub'), {
  onEnter(args) {
    const interpreter = args[0];
    const stack = interpreter.readPointer();

    const sub = stack.readPointer();

    const flags = sub.add(SV_OFFSET_FLAGS).readU32();
    const type = flags & 0xff;
    if (type === SVt_PVGV) {
      /*
       * Note: this console.log() is not ideal performance-wise,
       * a proper implementation would buffer and submit events
       * periodically with send().
       */
      console.log(GvNAME(sub) + '()');
    } else {
      // XXX: Do we need to handle other types?
    }
  }
});

function GvNAME(sv) {
  const body = sv.readPointer();
  const nameHek = body.add(PVGV_OFFSET_NAMEHEK).readPointer();
  return nameHek.add(8).readUtf8String();
}