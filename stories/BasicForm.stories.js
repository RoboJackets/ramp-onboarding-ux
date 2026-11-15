import { renderElmApp } from './elmHarness';
import { serverData } from './serverData';

export default {
    title: 'Onboarding Form/Basic',
    render: (args) => renderElmApp({
        serverData: args.serverData,
        localData: JSON.stringify(args.localData),
        storybookState: args.storybookState,
    }),
    args: {
        serverData,
        localData: { orderPhysicalCard: true },
    },
};
export const Ready = {};

export const EmailVerified = {
    args: {
        serverData: { ...serverData, emailVerified: true },
    },
};