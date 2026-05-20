async function get<T>(
  path: string,
  signal?: AbortSignal
): Promise<ResponseWithData<T>> {
  const response = await fetch(`${base}${path}`, {
    ...defaultOptions,
    headers: { 'CSRF-Token': getCSRFToken() },
    signal
  });

  return combineDataWithResponse(response);
}
