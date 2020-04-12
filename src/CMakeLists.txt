add_subdirectory(tpm12)

add_library(libtpms_tpm12 
    $<TARGET_OBJECTS:tpm12_objects>
    tpm_tpm12_interface.c
	tpm_tpm12_tis.c
)

