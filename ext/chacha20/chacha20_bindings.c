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

static VALUE rb_chacha20_set_nonce(VALUE self, VALUE nonce) {
  ECRYPT_ctx *ctx;

  Check_Type(nonce, RUBY_T_STRING);

  Data_Get_Struct(self, ECRYPT_ctx, ctx);

  ECRYPT_ivsetup(ctx, (const unsigned char*)RSTRING_PTR(nonce));

  return self;
}

static VALUE rb_chacha20_get_nonce(VALUE self) {
  VALUE output;
  ECRYPT_ctx *ctx;

  Data_Get_Struct(self, ECRYPT_ctx, ctx);

  output = rb_str_new(0, 8);
  memcpy(RSTRING_PTR(output), &ctx->input[14], 8);

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

static VALUE rb_chacha20_encrypt_or_decrypt(VALUE self, VALUE input, VALUE outbuf) {
  ECRYPT_ctx *ctx;

  Check_Type(input, RUBY_T_STRING);
  Check_Type(outbuf, RUBY_T_STRING);

  if (RSTRING_LEN(outbuf) != RSTRING_LEN(input)) {
    rb_raise(rb_eArgError, "Output buffer must have the same size as the input");
  }

  Data_Get_Struct(self, ECRYPT_ctx, ctx);

  ECRYPT_encrypt_bytes(ctx, (const unsigned char*)RSTRING_PTR(input), (unsigned char*)RSTRING_PTR(outbuf), (unsigned int)RSTRING_LEN(input));

  return outbuf;
}

void Init_chacha20_bindings() {
  cChaCha20 = rb_define_class("ChaCha20", rb_cObject);

  rb_define_alloc_func(cChaCha20, rb_chacha20_alloc);

  rb_define_private_method(cChaCha20, "init_context", rb_chacha20_init_context, 2);
  rb_define_private_method(cChaCha20, "set_nonce", rb_chacha20_set_nonce, 1);
  rb_define_private_method(cChaCha20, "get_nonce", rb_chacha20_get_nonce, 0);
  rb_define_private_method(cChaCha20, "set_counter", rb_chacha20_set_counter, 1);
  rb_define_private_method(cChaCha20, "get_counter", rb_chacha20_get_counter, 0);
  rb_define_private_method(cChaCha20, "encrypt_or_decrypt", rb_chacha20_encrypt_or_decrypt, 2);
}
