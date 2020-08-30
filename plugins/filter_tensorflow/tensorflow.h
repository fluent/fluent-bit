#ifndef FLB_FILTER_TENSORFLOW_H
#define FLB_FILTER_TENSORFLOW_H

struct flb_tensorflow {
    TfLiteModel* model;
    TfLiteInterpreterOptions* interpreter_options;
    TfLiteInterpreter* interpreter;
    flb_sds_t input_field;
    TfLiteType input_tensor_type;
    TfLiteType output_tensor_type;

    // IO buffer
    void* input;
    void* output;
    int input_size;
    int input_byte_size;
    int output_size;
    int output_byte_size;

    // feature scaling/normalization
    bool include_input_fields;
    float* normalization_value;

    struct flb_filter_instance *ins;
};

#endif
