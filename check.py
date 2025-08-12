with open('veles/secret.go') as f:
  for line in f.readlines():
    if line.endswith('\n'):
      print('line ends with \\n')
    if line.endswith('\n\r'):
      print('line ends with \\n\\r')
