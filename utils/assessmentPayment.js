export const assessmentPaymentState = (feeStatus) => {
  const confirmed = feeStatus === "payment-confirmed";
  return {
    confirmed,
    scheduledFeeStatus: confirmed ? "payment-confirmed" : feeStatus || "not-requested",
  };
};

export const initialAssessmentInspection = ({ feeAmount, paymentConfirmed, completed, now = new Date() }) => {
  if (completed) {
    return {
      feeAmount: feeAmount > 0 ? feeAmount : null,
      feeStatus: "payment-confirmed",
      status: "completed",
      completedAt: now,
      paymentConfirmedAt: now,
    };
  }

  return {
    feeAmount,
    feeStatus: paymentConfirmed ? "payment-confirmed" : "not-requested",
    status: "not-scheduled",
    paymentConfirmedAt: paymentConfirmed ? now : null,
  };
};
