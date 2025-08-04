pod_files = [
  'TPM_IO_Hash_Start.pod',
  'TPM_IO_TpmEstablished_Get.pod',
  'TPM_Malloc.pod',
  'TPMLIB_CancelCommand.pod',
  'TPMLIB_ChooseTPMVersion.pod',
  'TPMLIB_DecodeBlob.pod',
  'TPMLIB_GetInfo.pod',
  'TPMLIB_GetTPMProperty.pod',
  'TPMLIB_GetVersion.pod',
  'TPMLIB_MainInit.pod',
  'TPMLIB_Process.pod',
  'TPMLIB_RegisterCallbacks.pod',
  'TPMLIB_SetBufferSize.pod',
  'TPMLIB_SetDebugFD.pod',
  'TPMLIB_SetProfile.pod',
  'TPMLIB_SetState.pod',
  'TPMLIB_ValidateState.pod',
  'TPMLIB_VolatileAll_Store.pod',
  'TPMLIB_WasManufactured.pod',
]

pod2man = find_program('pod2man', required: true)

foreach pod : pod_files
  base_name = pod.split('.')[0]
  target_name = base_name + '.3'
  
  custom_target(target_name,
    input: pod,
    output: target_name,
    command: [pod2man, '-r', 'libtpms', '-c', '""', '-n', base_name, '--section=3', '@INPUT@', '@OUTPUT@'],
    capture: false,
    install: true,
    install_dir: get_option('mandir') / 'man3'
  )
endforeach
