import reducer, { fetchApi, initialState } from "./apiSlice";
import { configureStore } from "@reduxjs/toolkit";
import { client } from "../client";

const mockApiReturn = {
  version: 1,
  route: "/v1",
  pubkey: "fake_pubkey",
  testnet: true,
  mode: "piwww",
  activeusersession: true,
};

const mockCsrfToken = "fake_csrf";

describe("Given the apiSlice", () => {
  let store;
  // spy on the method used to fetch
  let fetchApiSpy;
  beforeEach(() => {
    // mock a minimal store with extra argument
    // re-create the store before each test
    store = configureStore({
      reducer,
      middleware: (getDefaultMiddleware) =>
        getDefaultMiddleware({
          // This will make the client available in the 'extra' argument
          // for all our thunks created with createAsyncThunk
          thunk: {
            extraArgument: client,
          },
        }),
    });
    fetchApiSpy = jest.spyOn(client, "fetchApi");
  });
  afterEach(() => {
    fetchApiSpy.mockRestore();
  });
  describe("when empty parameters", () => {
    it("should return the initial state", () => {
      expect(reducer(undefined, {})).toEqual(initialState);
    });
  });
  describe("when fetchApi dispatches", () => {
    it("should update the status to loading", () => {
      store.dispatch(fetchApi());
      expect(fetchApiSpy).toBeCalled();
      const state = store.getState();
      expect(state.status).toEqual("loading");
    });
  });
  describe("when fetchApi succeeds", () => {
    it("should update api state and csrf token", async () => {
      fetchApiSpy.mockResolvedValueOnce({
        api: mockApiReturn,
        csrf: mockCsrfToken,
      });
      await store.dispatch(fetchApi());
      expect(fetchApiSpy).toBeCalled();
      const state = store.getState();
      expect(state.api).toEqual(mockApiReturn);
      expect(state.csrf).toEqual(mockCsrfToken);
      expect(state.status).toEqual("succeeded");
    });
  });
  describe("when fetchApi fails", () => {
    it("should dispatch failure and update the error", async () => {
      const error = new Error("FAIL!");
      fetchApiSpy.mockRejectedValue(error);
      await store.dispatch(fetchApi());
      expect(fetchApiSpy).toBeCalled();
      const state = store.getState();
      expect(state.api).toEqual({});
      expect(state.csrf).toEqual("");
      expect(state.status).toEqual("failed");
      expect(state.error).toEqual("FAIL!");
    });
  });
});
