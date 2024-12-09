#include <ruby.h>
#include "ecrypt-sync.h"

static VALUE cChaCha20;

static VALUE rb_chacha20_alloc(VALUE klass) {
  VALUE obj;
  ECRYPT_ctx *ctx;

  obj = Data_Make_Struct(klass, ECRYPT_ctx, 0, 0, ctx);
  return obj;
}

static VALUE rb_chacha20_init_context(VALUE self, VALUE key, VALUE nonce) {
  ECRYPT_ctx *ctx;

  Check_Type(key, RUBY_T_STRING);
  Check_Type(nonce, RUBY_T_STRING);

  Data_Get_Struct(self, ECRYPT_ctx, ctx);

  ECRYPT_keysetup(ctx, (const unsigned char*)RSTRING_PTR(key), (unsigned int)RSTRING_LEN(key) * 8, 64);
  ECRYPT_ivsetup(ctx, (const unsigned char*)RSTRING_PTR(nonce));

  return self;
}

static VALUE rb_chacha20_keystream(VALUE self, VALUE length) {
  VALUE output;
  ECRYPT_ctx *ctx;

  Check_Type(length, RUBY_T_FIXNUM);

  Data_Get_Struct(self, ECRYPT_ctx, ctx);

  long length_long = NUM2LONG(length);
  output = rb_str_new(0, length_long);
  ECRYPT_keystream_bytes(ctx, (unsigned char*)RSTRING_PTR(output), (u32)length_long);

  return output;
}

static VALUE rb_chacha20_encrypt_or_decrypt(VALUE self, VALUE input) {
  VALUE output;
  ECRYPT_ctx *ctx;

  Check_Type(input, RUBY_T_STRING);

  Data_Get_Struct(self, ECRYPT_ctx, ctx);

  output = rb_str_new(0, RSTRING_LEN(input));
  ECRYPT_encrypt_bytes(ctx, (const unsigned char*)RSTRING_PTR(input), (unsigned char*)RSTRING_PTR(output), (unsigned int)RSTRING_LEN(input));

  return output;
}

static VALUE rb_chacha20_set_counter(VALUE self, VALUE counter) {
  ECRYPT_ctx *ctx;

  Check_Type(counter, RUBY_T_FIXNUM);

  Data_Get_Struct(self, ECRYPT_ctx, ctx);

  unsigned long long counter_ull = NUM2ULL(counter);
  ctx->input[12] = (u32)counter_ull;
  ctx->input[13] = (u32)(counter_ull >> 32);

  return Qnil;
}

static VALUE rb_chacha20_get_counter(VALUE self) {
  ECRYPT_ctx *ctx;

  Data_Get_Struct(self, ECRYPT_ctx, ctx);

  return rb_ull2inum(((unsigned LONG_LONG)(ctx->input[13]) << 32) | (unsigned LONG_LONG)(ctx->input[12]));
}

void Init_chacha20_bindings() {
  cChaCha20 = rb_define_class("ChaCha20", rb_cObject);

  rb_define_alloc_func(cChaCha20, rb_chacha20_alloc);

  rb_define_private_method(cChaCha20, "init_context", rb_chacha20_init_context, 2);
  rb_define_private_method(cChaCha20, "keystream", rb_chacha20_keystream, 1);
  rb_define_private_method(cChaCha20, "encrypt_or_decrypt", rb_chacha20_encrypt_or_decrypt, 1);
  rb_define_private_method(cChaCha20, "set_counter", rb_chacha20_set_counter, 1);
  rb_define_private_method(cChaCha20, "get_counter", rb_chacha20_get_counter, 0);
}
