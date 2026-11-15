import { renderElmApp } from './elmHarness';

export default {
  title: 'Errors/Null Server Data',
  render: () => renderElmApp({
    serverData: null,
    localData: "",
  }),
};

export const Default = {};
