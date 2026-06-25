# Build-time secret. The Docker `compile` stage overwrites this with the real
# base64 MODEL-KEK from the SECUREPROMPT_PINNED_MODEL_KEK build-arg, then Cython
# compiles this module to a .so and strips the source. Empty in source control.
MODEL_KEK_B64 = ""
