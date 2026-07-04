"use client";

import { useActionState, useEffect, useState } from "react";
import { Send } from "lucide-react";
import { enquiryTypes, preferredScanDepths } from "@/lib/contact/options";
import {
  submitContactEnquiry,
  type ContactFormState,
} from "@/app/contact/actions";

const initialState: ContactFormState = { ok: false, values: {} };

function FieldError({ errors }: { errors?: string[] }) {
  if (!errors?.length) return null;
  return <p className="mt-2 text-xs text-red-300">{errors[0]}</p>;
}

function value(state: ContactFormState, key: string) {
  return state.values?.[key] ?? "";
}

export function ContactForm() {
  const [state, formAction, pending] = useActionState(
    submitContactEnquiry,
    initialState,
  );
  const [startedAt, setStartedAt] = useState("");

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      setStartedAt(Date.now().toString());
    }, 0);
    return () => window.clearTimeout(timeout);
  }, []);

  if (state.ok) {
    return (
      <section className="panel p-7">
        <p className="eyebrow">Contact</p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight">
          Enquiry received
        </h1>
        <p className="mt-3 text-sm leading-6 text-slate-400">{state.message}</p>
      </section>
    );
  }

  return (
    <form action={formAction} className="panel p-5 sm:p-7">
      <input name="startedAt" type="hidden" value={startedAt} />
      <input name="sourcePage" type="hidden" value="/contact" />
      <label className="sr-only" htmlFor="website">
        Website
      </label>
      <input
        autoComplete="off"
        className="hidden"
        id="website"
        name="website"
        tabIndex={-1}
      />

      <div className="border-b border-line pb-5">
        <p className="eyebrow">Contact Probeveil</p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight">
          Talk to us
        </h1>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          Do not submit passwords, access tokens, private keys or other
          sensitive credentials through this form.
        </p>
      </div>

      {state.message && !state.ok && (
        <div className="mt-5 rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-200">
          {state.message}
        </div>
      )}

      <div className="mt-6 grid gap-5 sm:grid-cols-2">
        <label className="block text-sm text-slate-300">
          Full name
          <input
            className="input mt-2"
            defaultValue={value(state, "fullName")}
            maxLength={120}
            name="fullName"
            required
          />
          <FieldError errors={state.errors?.fullName} />
        </label>
        <label className="block text-sm text-slate-300">
          Work email
          <input
            autoComplete="email"
            className="input mt-2"
            defaultValue={value(state, "email")}
            maxLength={254}
            name="email"
            required
            type="email"
          />
          <FieldError errors={state.errors?.email} />
        </label>
        <label className="block text-sm text-slate-300">
          Company or organisation
          <input
            className="input mt-2"
            defaultValue={value(state, "company")}
            maxLength={160}
            name="company"
          />
          <FieldError errors={state.errors?.company} />
        </label>
        <label className="block text-sm text-slate-300">
          Role or job title
          <input
            className="input mt-2"
            defaultValue={value(state, "role")}
            maxLength={120}
            name="role"
          />
          <FieldError errors={state.errors?.role} />
        </label>
        <label className="block text-sm text-slate-300">
          Enquiry type
          <select
            className="input mt-2"
            defaultValue={value(state, "enquiryType")}
            name="enquiryType"
            required
          >
            <option value="">Select an option</option>
            {enquiryTypes.map(([optionValue, label]) => (
              <option key={optionValue} value={optionValue}>
                {label}
              </option>
            ))}
          </select>
          <FieldError errors={state.errors?.enquiryType} />
        </label>
        <label className="block text-sm text-slate-300">
          Website URL
          <input
            className="input mt-2"
            defaultValue={value(state, "websiteUrl")}
            maxLength={2048}
            name="websiteUrl"
            placeholder="https://example.com"
            type="url"
          />
          <FieldError errors={state.errors?.websiteUrl} />
        </label>
        <label className="block text-sm text-slate-300">
          Estimated number of websites
          <input
            className="input mt-2"
            defaultValue={value(state, "estimatedWebsiteCount")}
            min={1}
            name="estimatedWebsiteCount"
            type="number"
          />
          <FieldError errors={state.errors?.estimatedWebsiteCount} />
        </label>
        <label className="block text-sm text-slate-300">
          Preferred scan depth
          <select
            className="input mt-2"
            defaultValue={value(state, "preferredScanDepth")}
            name="preferredScanDepth"
          >
            <option value="">Select an option</option>
            {preferredScanDepths.map(([optionValue, label]) => (
              <option key={optionValue} value={optionValue}>
                {label}
              </option>
            ))}
          </select>
          <FieldError errors={state.errors?.preferredScanDepth} />
        </label>
      </div>

      <label className="mt-5 block text-sm text-slate-300">
        Message
        <textarea
          className="input mt-2 min-h-40 resize-y"
          defaultValue={value(state, "message")}
          maxLength={5000}
          name="message"
          required
        />
        <FieldError errors={state.errors?.message} />
      </label>

      <label className="mt-5 flex gap-3 text-sm leading-6 text-slate-400">
        <input
          className="mt-1 rounded border-line bg-[#0b0f14] text-signal focus:ring-signal/20"
          defaultChecked={value(state, "consent") === "on"}
          name="consent"
          required
          type="checkbox"
        />
        I agree that Probeveil may process this enquiry and contact me about it.
      </label>
      <FieldError errors={state.errors?.consent} />

      <button
        className="button mt-6 w-full sm:w-auto"
        disabled={pending || !startedAt}
      >
        <Send size={16} />
        {pending ? "Sending..." : "Send enquiry"}
      </button>
    </form>
  );
}
